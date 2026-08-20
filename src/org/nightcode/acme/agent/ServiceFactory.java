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

package org.nightcode.acme.agent;

import java.io.Closeable;

import org.nightcode.acme.agent.service.CertificateUpdateService;
import org.nightcode.acme.agent.service.acme.AcmeService;
import org.nightcode.acme.agent.service.acme.AcmeServiceImpl;
import org.nightcode.acme.agent.service.dns.Dns;
import org.nightcode.acme.agent.service.dns.DnsOperations;
import org.nightcode.acme.agent.service.dns.DnsProvider;
import org.nightcode.acme.agent.service.dns.VanillaDns;
import org.nightcode.acme.agent.service.dns.impl.BindDnsProvider;
import org.nightcode.acme.agent.service.dns.impl.CloudflareDnsProvider;
import org.nightcode.common.service.ServiceContext;
import org.nightcode.common.util.Closeables;

class ServiceFactory implements Closeable {

  static DnsProvider dnsProvider(ServerConfig config) {
    return switch (config.getDnsProvider()) {
      case BIND -> new BindDnsProvider(config.getBind());
      case CLOUDFLARE -> new CloudflareDnsProvider(config.getCloudflare());
    };
  }

  private final ServerConfig   config;
  private final ServiceContext context;

  ServiceFactory(ServerConfig config, ServiceContext context) {
    this.config  = config;
    this.context = context;
  }

  @Override public void close() {
    Closeables.close(context);
  }

  Dns dns() {
    return context.registerService(Dns.class, () -> new VanillaDns(dnsProvider(config), DnsOperations.def()));
  }

  AcmeService acmeService() {
    return context.registerService(AcmeService.class, () -> new AcmeServiceImpl(config.getAcme(), dns()));
  }

  CertificateUpdateService certificateUpdateService() {
    return context.registerService(CertificateUpdateService.class, () -> new CertificateUpdateService(config, acmeService()));
  }
}
