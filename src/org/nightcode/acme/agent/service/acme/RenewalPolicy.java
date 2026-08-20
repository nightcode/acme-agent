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

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

public interface RenewalPolicy {

  RenewalPolicy DEFAULT = (certificate, certDaysTtl, now) -> {
    Instant threshold = now.plus(Duration.ofDays(certDaysTtl));
    return certificate.getNotAfter().toInstant().isBefore(threshold);
  };

  static RenewalPolicy def() {
    return DEFAULT;
  }

  boolean renewalDue(X509Certificate certificate, int certDaysTtl, Instant now);
}
