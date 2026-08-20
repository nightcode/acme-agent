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

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.shredzone.acme4j.connector.NetworkSettings;
import org.shredzone.acme4j.provider.GenericAcmeProvider;

class CustomCaAcmeProvider extends GenericAcmeProvider {

  static SSLContext createSslContext(Path customCa) {
    try (InputStream is = Files.newInputStream(customCa)) {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      Collection<? extends Certificate> cas = factory.generateCertificates(is);
      if (cas.isEmpty()) {
        throw new IllegalStateException("no certificates found in " + customCa);
      }

      KeyStore trustStore = KeyStore.getInstance("PKCS12");
      trustStore.load(null, null);
      int index = 0;
      for (Certificate ca : cas) {
        trustStore.setCertificateEntry("ca-" + index++, ca);
      }
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);

      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, tmf.getTrustManagers(), null);
      return context;
    } catch (GeneralSecurityException | IOException ex) {
      throw new IllegalStateException("cannot build a trust store from custom CA " + customCa, ex);
    }
  }

  private final SSLContext sslContext;

  CustomCaAcmeProvider(Path caBundle) {
    this.sslContext = createSslContext(caBundle);
  }

  @Override public HttpClient createHttpClient(NetworkSettings settings) {
    HttpClient.Builder builder = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .connectTimeout(settings.getTimeout())
        .proxy(settings.getProxySelector())
        .sslContext(sslContext);
    if (settings.getAuthenticator() != null) {
      builder.authenticator(settings.getAuthenticator());
    }
    return builder.build();
  }
}
