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

package org.nightcode.acme.agent.service.dns.impl.cloudflare.json;

import com.google.api.client.util.Key;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
@ToString
public class DnsRecord {

  @Key("id")          String  id;
  @Key("type")        String  type;
  @Key("name")        String  name;
  @Key("content")     String  content;
  @Key("proxiable")   Boolean proxiable;
  @Key("proxied")     Boolean proxied;
  @Key("ttl")         Integer ttl;
  @Key("locked")      Boolean locked;
  @Key("zone_id")     String  zoneId;
  @Key("zone_name")   String  zoneName;
  @Key("modified_on") String  modifiedOn;
  @Key("created_on")  String  createdOn;
  @Key("meta")        Meta    meta;
}
