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

import org.nightcode.acme.agent.service.dns.DnsProvider;
import org.nightcode.acme.agent.service.dns.RecordType;
import org.nightcode.common.logging.Log;

public class ManualDnsProvider implements DnsProvider {

  private final String zone;

  public ManualDnsProvider(String zone) {
    this.zone = zone;
  }

  @Override public void addRecord(RecordType type, String name, String value) {
    Log.info().log(getClass(), "please add a '{}' record to zone {}:\n {} IN {} {}", type, zone, name, type, value);
  }

  @Override public void deleteRecord(RecordType type, String name, String value) {
    Log.info().log(getClass(), "please delete a '{}' record from zone {}:\n {} IN {}..", type, zone, name, type, value);
  }
}
