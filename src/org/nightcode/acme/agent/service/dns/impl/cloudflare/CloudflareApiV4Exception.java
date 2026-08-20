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

import java.util.List;

import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.DnsError;

import lombok.Getter;

@Getter
public class CloudflareApiV4Exception extends Exception {

  private final List<DnsError> errors;

  public CloudflareApiV4Exception(String message, List<DnsError> errors) {
    super(message, null, true, false);
    this.errors = errors;
  }

  @Override public String getMessage() {
    return super.getMessage() + ": " + errors;
  }
}
