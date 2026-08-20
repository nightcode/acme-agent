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

package org.nightcode.acme.agent.service.dns.impl;

import org.nightcode.acme.agent.service.dns.RecordType;
import org.xbill.DNS.Type;

public enum DnsUtils {
  ;

  public static int bindRecordTypeOf(RecordType type) {
    return switch (type) {
      case A -> Type.A;
      case AAAA -> Type.AAAA;
      case CNAME -> Type.CNAME;
      case MX -> Type.MX;
      case TXT -> Type.TXT;
      default -> throw new IllegalArgumentException("unsupported record type: " + type);
    };
  }
}
