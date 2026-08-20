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
import java.net.InetSocketAddress;
import java.time.Duration;

import org.nightcode.acme.agent.config.BindConfig;
import org.nightcode.acme.agent.service.dns.DnsProvider;
import org.nightcode.acme.agent.service.dns.RecordType;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Update;

import static org.nightcode.acme.agent.service.dns.impl.DnsUtils.bindRecordTypeOf;

public class BindDnsProvider implements DnsProvider {

  public static Name of(String name) {
    try {
      return Name.fromString(name, Name.root);
    } catch (TextParseException ex) {
      throw new IllegalArgumentException("invalid DNS name: " + name, ex);
    }
  }

  private final BindConfig        config;
  private final InetSocketAddress address;
  private final Name              zone;
  private final TSIG              tsig;

  public BindDnsProvider(BindConfig config) {
    this.config = config;
    address     = new InetSocketAddress(config.getServer(), config.getPort());
    tsig        = new TSIG(TSIG.algorithmToName(config.getTsigAlgorithm()), of(config.getTsigKeyName()), config.getTsigSecret());
    zone        = of(config.getDynamicZone());
  }

  @Override public void addRecord(RecordType type, String name, String value) {
    Update update = new Update(zone, DClass.IN);
    try {
      update.add(of(name), bindRecordTypeOf(type), config.getTtlSec(), value);
    } catch (IOException ex) {
      throw new IllegalStateException("cannot build DNS update for " + name, ex);
    }
    send(update);
  }

  @Override public void deleteRecord(RecordType type, String name, String value) {
    Update update = new Update(zone, DClass.IN);
    update.delete(of(name), bindRecordTypeOf(type));
    send(update);
  }

  private void send(Update update) {
    SimpleResolver resolver = new SimpleResolver(address);
    resolver.setTCP(config.isTcp());
    resolver.setTimeout(Duration.ofSeconds(10));
    resolver.setTSIGKey(tsig);

    try {
      Message response = resolver.send(update);
      int     rcode    = response.getRcode();
      if (rcode != Rcode.NOERROR) {
        throw new IllegalStateException("DNS update rejected by " + address + ": " + Rcode.string(rcode));
      }
    } catch (IOException ex) {
      throw new IllegalStateException("DNS update failed: " + ex.getMessage(), ex);
    }
  }
}
