/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.nightcode.acme.agent.service.acme;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.nightcode.acme.agent.config.AcmeConfig;
import org.nightcode.acme.agent.model.CertificateIssuingException;
import org.nightcode.acme.agent.model.CsrTask;
import org.nightcode.acme.agent.model.SignedCertificateResult;
import org.nightcode.acme.agent.service.dns.Dns;
import org.nightcode.acme.agent.service.dns.RecordType;
import org.nightcode.acme.agent.service.dns.impl.BindDnsProvider;
import org.nightcode.acme.agent.util.CnameResolver;
import org.nightcode.common.logging.Log;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Problem;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.provider.AcmeProvider;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;

import static org.nightcode.acme.agent.service.dns.impl.DnsUtils.bindRecordTypeOf;

public class AcmeServiceImpl implements AcmeService {

  private static final Duration ACME_TIMEOUT = Duration.ofSeconds(60);
  private static final Duration DNS_TIMEOUT  = Duration.ofSeconds(60);

  private static final int MAX_CHAIN_LENGTH = 10;

  private final URI serverUri;
  private final Dns dns;

  private final String  email;
  private final KeyPair keyPair;

  private final AcmeProvider  provider;

  public AcmeServiceImpl(AcmeConfig acme, Dns dns) {
    this.dns       = dns;
    this.serverUri = URI.create(acme.getUri());
    this.email     = acme.getEmail();

    String customCa = acme.getCustomCaPath();
    this.provider = (customCa == null || customCa.isEmpty()) ? null : new CustomCaAcmeProvider(Paths.get(customCa));

    try (Reader r = new FileReader(acme.getAccountKeyPairPath())) {
      keyPair = KeyPairUtils.readKeyPair(r);
    } catch (IOException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override public Account findOrRegisterAccount(Session session) throws AcmeException {
    Account account = new AccountBuilder()
        .useKeyPair(keyPair)
        .addEmail(email)
        .agreeToTermsOfService()
        .create(session);
    if (!account.getStatus().equals(Status.VALID)) {
      throw new IllegalStateException("invalid account status: " + account.getStatus());
    }
    return account;
  }

  @Override public SignedCertificateResult issueCertificate(CsrTask task) throws CertificateIssuingException {
    Session session = provider == null ? new Session(serverUri) : new Session(serverUri, provider);

    try {
      Account account = findOrRegisterAccount(session);
      Order   order   = account.newOrder().domains(task.domains()).create();

      authorize(order);

      Certificate certificate = executeOrder(order, task.csr());

      Log.info().log(getClass(), "Success! The certificate for domains {} has been generated!", task.domains());
      Log.info().log(getClass(), "Certificate URL: {}", certificate.getLocation());

      return createCertificateResult(certificate);
    } catch (AcmeException ex) {
      throw new CertificateIssuingException("unable to issue certificate for domains " + task.domains(), ex);
    }
  }

  private void authorize(Order order) throws AcmeException {
    Authorization authorization = tryFirstOnly(order.getAuthorizations());
    if (Status.VALID.equals(authorization.getStatus())) {
      return;
    }

    Dns01Challenge challenge = authorization.findChallenge(Dns01Challenge.TYPE)
        .map(Dns01Challenge.class::cast)
        .orElseThrow(() -> new AcmeException("found no " + Dns01Challenge.TYPE + " challenge"));

    String rrName   = challenge.getRRName(authorization.getIdentifier());
    String txtName  = resolveTxtName(rrName); // the CNAME-chain target when the challenge is delegated
    String txtValue = normalizeTxtValue(challenge.getDigest());

    dns.addRecord(RecordType.TXT, txtName, txtValue);
    try {
      dnsLookup(RecordType.TXT, txtName);
      processChallenge(challenge);
    } finally {
      dns.deleteRecord(RecordType.TXT, txtName, txtValue);
    }
  }

  private String resolveTxtName(String rrName) throws AcmeException {
    Name start = BindDnsProvider.of(rrName);
    try {
      return CnameResolver.resolve(start, MAX_CHAIN_LENGTH).toString();
    } catch (IOException ex) {
      throw new AcmeException("cannot resolve the CNAME chain of " + rrName, ex);
    }
  }

  private SignedCertificateResult createCertificateResult(Certificate acmeCertificate) {
    Objects.requireNonNull(acmeCertificate, "acmeCertificate");
    Objects.requireNonNull(acmeCertificate.getCertificate(), "acmeCertificate.Certificate");
    return new SignedCertificateResult(acmeCertificate.getCertificate(), removeFirst(acmeCertificate.getCertificateChain()));
  }

  private Certificate executeOrder(Order order, PKCS10CertificationRequest csr) throws AcmeException {
    try {
      order.waitUntilReady(ACME_TIMEOUT);

      order.execute(csr);

      Status status = order.waitForCompletion(ACME_TIMEOUT);
      if (!Status.VALID.equals(status)) {
        throw new AcmeException("order has failed, reason: " + order.getError().map(Problem::toString).orElse("unknown"));
      }

      return order.getCertificate();
    } catch (InterruptedException ex) {
      throw new AcmeException("cannot execute order", ex);
    }
  }

  private String normalizeTxtValue(String txtValue) {
    boolean needHead = txtValue.charAt(0) != '\"';
    boolean needTail = txtValue.charAt(txtValue.length() - 1) != '\"';
    if (!needHead && !needTail) {
      return txtValue;
    }
    char[] chars;
    if (needHead && needTail) {
      chars = new char[txtValue.length() + 2];
      System.arraycopy(txtValue.toCharArray(), 0, chars, 1, txtValue.length());
      chars[0]                = '"';
      chars[chars.length - 1] = '"';
    } else {
      chars = new char[txtValue.length() + 1];
      int offset = needHead ? 1 : 0;
      int pos    = needHead ? 0 : chars.length - 1;
      System.arraycopy(txtValue.toCharArray(), 0, chars, offset, txtValue.length());
      chars[pos] = '"';
    }
    return new String(chars);
  }

  private void processChallenge(Challenge challenge) throws AcmeException {
    if (Status.VALID.equals(challenge.getStatus())) {
      return;
    }

    challenge.trigger();

    Status status;
    try {
      status = challenge.waitForCompletion(ACME_TIMEOUT);
    } catch (InterruptedException ex) {
      throw new AcmeException("cannot receive challenge status", ex);
    }

    if (!Status.VALID.equals(status)) {
      throw new AcmeException("challenge has failed, reason: " + challenge.getError().map(Problem::toString).orElse("unknown"));
    }
  }

  private Authorization tryFirstOnly(List<Authorization> authorizations) {
    if (authorizations.size() != 1) {
      throw new IllegalStateException("authorizations should contain only one element but not " + authorizations.size());
    }
    return authorizations.getFirst();
  }

  private List<X509Certificate> removeFirst(List<X509Certificate> chain) {
    return chain.subList(1, chain.size());
  }

  private void dnsLookup(RecordType type, String name) throws AcmeException {
    Log.info().log(getClass(), "DNS lookup for record '{}' {} ...", type, name);

    int  bindType = bindRecordTypeOf(type);
    Name lookup   = BindDnsProvider.of(name);

    Instant threshold = Instant.now().plus(DNS_TIMEOUT);
    for (Instant now = Instant.now(); now.isBefore(threshold); now = Instant.now()) {
      try {
        LookupSession session = LookupSession.defaultBuilder().build();
        LookupResult  result  = session.lookupAsync(lookup, bindType).toCompletableFuture().join();

        Log.info().log(getClass(), "DNS {}", result);
        if (!result.getRecords().isEmpty()) {
          return;
        }

        Instant retryAfter = now.plus(1, ChronoUnit.SECONDS);
        if (retryAfter.isAfter(threshold)) {
          break;
        }
        Thread.sleep(now.until(retryAfter, ChronoUnit.MILLIS));
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        throw new AcmeException("interrupted during a DNS lookup for record '" + type + "' " + name, ex);
      }
    }

    throw new AcmeException("DNS lookup timeout for record '" + type + "' " + name);
  }
}
