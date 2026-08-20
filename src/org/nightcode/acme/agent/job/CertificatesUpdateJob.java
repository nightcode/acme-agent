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

package org.nightcode.acme.agent.job;

import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.nightcode.acme.agent.ServerConfig;
import org.nightcode.acme.agent.config.CertificateInfo;
import org.nightcode.acme.agent.config.CertificateTask;
import org.nightcode.acme.agent.model.CsrTask;
import org.nightcode.acme.agent.model.SignedCertificateResult;
import org.nightcode.acme.agent.service.acme.AcmeService;
import org.nightcode.acme.agent.service.acme.RenewalPolicy;
import org.nightcode.common.logging.Log;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;

import static java.util.Collections.singletonList;

public class CertificatesUpdateJob extends CronJob {

  private static final String CERTIFICATE_OBJECT_TYPE = "CERTIFICATE";
  private static final String PRIVATE_KEY_OBJECT_TYPE = "PRIVATE KEY";

  private static final DateTimeFormatter ARCHIVE_STAMP = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

  private static final Set<PosixFilePermission> OWNER_ONLY_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private static final Set<PosixFilePermission> CERTIFICATE_PERMISSIONS = EnumSet.of(PosixFilePermission.OWNER_WRITE
      , PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);

  private static final FileAttribute<Set<PosixFilePermission>> OWNER_ONLY = PosixFilePermissions.asFileAttribute(OWNER_ONLY_PERMISSIONS);

  private static KeyPair create(String keyType) {
    return switch (keyType) {
      case "ec256" -> KeyPairUtils.createECKeyPair("secp256r1");
      case "ec384" -> KeyPairUtils.createECKeyPair("secp384r1");
      case "rsa2048" -> KeyPairUtils.createKeyPair(2048);
      case "rsa4096" -> KeyPairUtils.createKeyPair(4096);
      default -> throw new IllegalArgumentException("unsupported keyType: " + keyType + " (expected one of ec256, ec384, rsa2048, rsa4096)");
    };
  }

  private final AcmeService           acmeService;
  private final List<CertificateTask> tasks;
  private final int                   certDaysTtl;
  private final int                   archiveRetention;

  public CertificatesUpdateJob(ServerConfig config, AcmeService acmeService) {
    this.acmeService      = acmeService;
    this.tasks            = config.getTasks();
    this.certDaysTtl      = config.getCertDaysTtl();
    this.archiveRetention = config.getArchiveRetention();
  }

  @Override public void executeInternal() {
    int failed = 0;
    for (CertificateTask task : tasks) {
      Log.info().log(getClass(), "executing task: " + task.toString());
      for (CertificateInfo cert : task.getCertificates()) {
        try {
          processCertificate(task, cert);
          Log.info().log(getClass(), "successfully executed task {} for domainName {}", task, cert.getDomainName());
        } catch (Exception ex) {
          failed++;
          Log.warn().log(getClass(), ex, "failed to execute task {} for domainName {}", task, cert.getDomainName());
        }
      }
    }
    if (failed > 0) {
      Log.error().log(getClass(), "{} certificate task(s) failed — see the warnings above", failed);
    }
  }

  private void processCertificate(CertificateTask task, CertificateInfo cert) throws Exception {
    String  type       = task.getType();
    String  domainName = cert.getDomainName();
    boolean combined   = "combined".equals(type);
    String  path       = task.getPath().endsWith("/") ? task.getPath() + domainName : task.getPath() + "/" + domainName;

    Path    crt       = Paths.get(path + ".crt");
    boolean crtExists = Files.exists(crt);
    if (crtExists) {
      try (InputStream is = new FileInputStream(path + ".crt")) {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509Certificate    certificate        = (X509Certificate) certificateFactory.generateCertificate(is);
        if (!RenewalPolicy.def().renewalDue(certificate, certDaysTtl, Instant.now())) {
          Log.info().log(getClass(), "certificate for domain '{}' does not need to be updated, expiration date is {}", domainName, certificate.getNotAfter());
          return;
        }
        Log.info().log(getClass(), "certificate for domain'{}' is expiring soon (not after {}), replacing...", domainName, certificate.getNotAfter());
      }
    } else {
      Log.info().log(getClass(), "certificate for domain '{}' does not exist, creating...", domainName);
    }

    KeyPair      keyPair = create(cert.getKeyType());
    List<String> domains = singletonList(domainName);
    CsrTask      csrTask = new CsrTask(domains, keyPair, csr(keyPair, domains));

    SignedCertificateResult signedCertificateResult = acmeService.issueCertificate(csrTask);

    Path tmpCrt = null;
    Path tmpKey = null;
    Path tmpCa  = null;
    try {
      tmpCrt = Paths.get(path + ".crt.tmp");
      Files.deleteIfExists(tmpCrt);
      Files.createFile(tmpCrt, OWNER_ONLY);

      tmpKey = Paths.get(path + ".key.tmp");
      Files.deleteIfExists(tmpKey);
      Files.createFile(tmpKey, OWNER_ONLY);

      if (combined) {
        try (PemWriter writer = new PemWriter(new FileWriter(tmpCrt.toString(), true))) {
          writer.writeObject(new PemObject(CERTIFICATE_OBJECT_TYPE, signedCertificateResult.certificate().getEncoded()));
          for (X509Certificate chain : signedCertificateResult.chain()) {
            writer.writeObject(new PemObject(CERTIFICATE_OBJECT_TYPE, chain.getEncoded()));
          }
        }
      } else {
        tmpCa = Paths.get(path + ".ca.tmp");
        Files.deleteIfExists(tmpCa);
        Files.createFile(tmpCa, OWNER_ONLY);

        try (PemWriter writer = new PemWriter(new FileWriter(tmpCrt.toString(), true))) {
          writer.writeObject(new PemObject(CERTIFICATE_OBJECT_TYPE, signedCertificateResult.certificate().getEncoded()));
        }

        try (PemWriter writer = new PemWriter(new FileWriter(tmpCa.toString(), true))) {
          for (X509Certificate chain : signedCertificateResult.chain()) {
            writer.writeObject(new PemObject(CERTIFICATE_OBJECT_TYPE, chain.getEncoded()));
          }
        }
      }

      try (PemWriter writer = new PemWriter(new FileWriter(tmpKey.toString()))) {
        writer.writeObject(new PemObject(PRIVATE_KEY_OBJECT_TYPE, keyPair.getPrivate().getEncoded()));
      }

      Path key = Paths.get(path + ".key");
      Path ca  = Paths.get(path + ".ca");

      String stamp   = ARCHIVE_STAMP.format(Instant.now());
      Path   keyPrev = Paths.get(path + ".key." + stamp);
      Path   crtPrev = Paths.get(path + ".crt." + stamp);
      Path   caPrev  = Paths.get(path + ".ca." + stamp);

      if (crtExists) {
        Files.move(crt, crtPrev, StandardCopyOption.REPLACE_EXISTING);
        Files.setPosixFilePermissions(crtPrev, CERTIFICATE_PERMISSIONS);
      }
      Files.move(tmpCrt, crt, StandardCopyOption.REPLACE_EXISTING);
      Files.setPosixFilePermissions(crt, CERTIFICATE_PERMISSIONS);

      if (!combined) {
        if (crtExists) {
          Files.move(ca, caPrev, StandardCopyOption.REPLACE_EXISTING);
          Files.setPosixFilePermissions(caPrev, CERTIFICATE_PERMISSIONS);
        }
        Files.move(tmpCa, ca, StandardCopyOption.REPLACE_EXISTING);
        Files.setPosixFilePermissions(ca, CERTIFICATE_PERMISSIONS);
      }

      if (crtExists) {
        Files.move(key, keyPrev, StandardCopyOption.REPLACE_EXISTING);
        Files.setPosixFilePermissions(keyPrev, OWNER_ONLY_PERMISSIONS);
      }
      Files.move(tmpKey, key, StandardCopyOption.REPLACE_EXISTING);
      Files.setPosixFilePermissions(key, OWNER_ONLY_PERMISSIONS);

      Log.info().log(getClass(), "certificate '{}' updated successfully", domainName);

      String restartCmd = task.getRestartCmd();
      if (restartCmd == null || restartCmd.isBlank()) {
        Log.info().log(getClass(), "no restartCmd for certificate '{}', skipping the service restart", domainName);
      } else {
        doRestart(restartCmd);
      }

      pruneArchives(crt.toAbsolutePath().getParent(), domainName);
    } finally {
      if (tmpKey != null) {
        Files.deleteIfExists(tmpKey);
      }
      if (tmpCrt != null) {
        Files.deleteIfExists(tmpCrt);
      }
      if (tmpCa != null) {
        Files.deleteIfExists(tmpCa);
      }
    }
  }

  private void pruneArchives(Path dir, String domainName) throws IOException {
    for (String suffix : List.of(".crt.", ".key.", ".ca.")) {
      String     prefix = domainName + suffix;
      List<Path> archives;
      try (Stream<Path> files = Files.list(dir)) {
        archives = files
            .filter(p -> p.getFileName().toString().startsWith(prefix))
            .filter(p -> !p.getFileName().toString().endsWith(".tmp"))
            .sorted(Comparator.comparing(p -> p.getFileName().toString()))
            .toList();
      }
      for (int i = 0; i + archiveRetention < archives.size(); i++) {
        Log.info().log(getClass(), "pruning rotated-out archive {}", archives.get(i));
        Files.deleteIfExists(archives.get(i));
      }
    }
  }

  private void doRestart(String cmd) throws IOException {
    Process restart = Runtime.getRuntime().exec(new String[]{"bash", "-c", cmd});
    try {
      restart.waitFor();
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
    int exitValue = restart.exitValue();
    if (exitValue != 0) {
      throw new RuntimeException("restart command returned unsuccessful response code: " + exitValue);
    }
  }

  private PKCS10CertificationRequest csr(KeyPair domainKeyPair, List<String> domains) throws IOException {
    CSRBuilder builder = new CSRBuilder();
    domains.forEach(builder::addDomain);
    builder.sign(domainKeyPair);
    return builder.getCSR();
  }
}
