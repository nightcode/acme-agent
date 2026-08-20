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

package org.nightcode.acme.agent.service.dns.impl.cloudflare;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.nightcode.common.logging.Log;

public enum SimpleHostnameVerifier implements HostnameVerifier {
  INSTANCE;

  @Override public boolean verify(String host, SSLSession session) {
    try {
      Certificate[]   certs = session.getPeerCertificates();
      X509Certificate x509  = (X509Certificate) certs[0];
      List<String>    cns   = getCns(x509);
      List<String>    alts  = getAlts(x509);

      Set<String> names = new TreeSet<>();
      if (!cns.isEmpty()) {
        names.add(cns.getFirst().toLowerCase());
      }
      for (String alt : alts) {
        if (alt != null) {
          names.add(alt.trim().toLowerCase());
        }
      }

      final String hostname = host.trim().toLowerCase();
      for (String cn : names) {
        boolean isWildCard = cn.startsWith("*.") && cn.lastIndexOf('.') != cn.length() - 1;
        if (isWildCard && hostname.endsWith(cn.substring(1)) || hostname.equals(cn)) {
          return true;
        }
      }

      return false;
    } catch (SSLException ex) {
      Log.info().log(getClass(), "can't verify hostname, SSL exception occurred", ex);
      return false;
    }
  }

  private List<String> getCns(X509Certificate cert) {
    List<String> cns              = new ArrayList<>();
    String       subjectPrincipal = cert.getSubjectX500Principal().toString();

    for (String part : subjectPrincipal.split(",")) {
      int i = part.indexOf("CN=");
      if (i != -1) {
        cns.add(part.substring(i + 3));
      }
    }

    return cns;
  }

  private List<String> getAlts(X509Certificate cert) {
    List<String> alts = new ArrayList<>();

    Collection<List<?>> san = null;
    try {
      san = cert.getSubjectAlternativeNames();
    } catch (CertificateParsingException ex) {
      Log.info().log(getClass(), "can't parse Subject Alternative names", ex);
    }

    if (san == null) {
      return alts;
    }

    for (List<?> l : san) {
      int type = (Integer) l.get(0);
      if (type == 2) {
        alts.add((String) l.get(1));
      }
    }

    return alts;
  }
}
