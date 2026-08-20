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

package org.nightcode.acme.agent.util;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.CompletionException;

import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;
import org.xbill.DNS.lookup.NoSuchDomainException;
import org.xbill.DNS.lookup.NoSuchRRSetException;

public enum CnameResolver {
  ;

  public static Name resolve(Name start, int maxChainLength) throws IOException {
    Name current = start;
    for (int i = 0; i < maxChainLength; i++) {
      Optional<Name> target = lookupCnameTarget(current);
      if (target.isEmpty()) {
        return current;
      }
      current = target.get();
    }
    throw new IOException("CNAME chain starting at '" + start + "' exceeds " + maxChainLength + " links");
  }

  private static Optional<Name> lookupCnameTarget(Name name) throws IOException {
    LookupSession session = LookupSession.defaultBuilder().build();
    try {
      LookupResult result = session.lookupAsync(name, Type.CNAME).toCompletableFuture().join();
      return result.getRecords().stream()
          .filter(CNAMERecord.class::isInstance)
          .map(record -> ((CNAMERecord) record).getTarget())
          .findFirst();
    } catch (CompletionException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof NoSuchDomainException || cause instanceof NoSuchRRSetException) {
        return Optional.empty();
      }
      throw new IOException("CNAME lookup failed for " + name, ex);
    }
  }
}
