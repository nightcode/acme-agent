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

import java.io.IOException;

import org.nightcode.acme.agent.config.CloudflareConfig;
import org.nightcode.acme.agent.service.dns.DnsProvider;
import org.nightcode.acme.agent.service.dns.RecordType;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.CloudflareApi;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.CloudflareApiV4Exception;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.ColudflareApiV4;

public class CloudflareDnsProvider implements DnsProvider {

  private static org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType of(RecordType type) {
    return switch (type) {
      case A -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.A;
      case AAAA -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.AAAA;
      case CNAME -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.CNAME;
      case HTTPS -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.HTTPS;
      case TXT -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.TXT;
      case SRV -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.SRV;
      case LOC -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.LOC;
      case MX -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.MX;
      case NS -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.NS;
      case SPF -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.SPF;
      case CERT -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.CERT;
      case DNSKEY -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.DNSKEY;
      case DS -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.DS;
      case NAPTR -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.NAPTR;
      case SMIMEA -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.SMIMEA;
      case SSHFP -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.SSHFP;
      case SVCB -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.SVCB;
      case TLSA -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.TLSA;
      case URI -> org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType.URI;
    };
  }

  private final CloudflareApi cloudflareApi;

  public CloudflareDnsProvider(CloudflareConfig config) {
    this.cloudflareApi = new ColudflareApiV4(config.getZoneId(), config.getToken());
  }

  @Override public void addRecord(RecordType type, String name, String value) {
    try {
      cloudflareApi.createDnsRecord(of(type), name, value);
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    } catch (CloudflareApiV4Exception ex) {
      throw new IllegalStateException(ex.getMessage());
    }
  }

  @Override public void deleteRecord(RecordType type, String name, String value) {
    try {
      cloudflareApi.deleteDnsRecord(of(type), name, value);
    } catch (IOException ex) {
      throw new IllegalStateException(ex.getMessage(), ex);
    } catch (CloudflareApiV4Exception ex) {
      throw new IllegalStateException(ex.getMessage());
    }
  }
}
