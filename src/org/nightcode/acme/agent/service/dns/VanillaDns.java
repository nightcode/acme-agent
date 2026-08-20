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

package org.nightcode.acme.agent.service.dns;

public class VanillaDns implements Dns {

  private final DnsProvider   provider;
  private final DnsOperations operations;

  public VanillaDns(DnsProvider provider, DnsOperations operations) {
    this.provider   = provider;
    this.operations = operations;
  }

  @Override public void addRecord(RecordType type, String name, String value) {
    RecordContext context = newRecordContext(name, type);
    Record        record  = context.record();
    context.addRecord(record, value);
  }

  @Override public void deleteRecord(RecordType type, String name, String value) {
    RecordContext context = newRecordContext(name, type);
    Record        record  = context.record();
    context.deleteRecord(record, value);
  }

  DnsOperations operations() {
    return operations;
  }

  DnsProvider provider() {
    return provider;
  }

  private RecordContext newRecordContext(String name, RecordType type) {
    return new RecordContextImpl(name, type, this);
  }
}
