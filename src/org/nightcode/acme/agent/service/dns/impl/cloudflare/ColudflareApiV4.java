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

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpRequestInitializer;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;

import java.io.IOException;
import java.net.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.nightcode.acme.agent.http.GsonHttpContent;
import org.nightcode.acme.agent.http.GsonObjectParser;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.AbstractResponse;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.CreateDnsRecord;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.CreateDnsRecordResponse;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.DeleteDnsRecordResponse;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.DnsRecord;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.ListDnsRecordsResponse;
import org.nightcode.acme.agent.service.dns.impl.cloudflare.json.RecordType;
import org.nightcode.common.logging.Log;

public class ColudflareApiV4 implements CloudflareApi {

  private static final int CONNECT_TIMEOUT_MS = (int) TimeUnit.SECONDS.toMillis(10);
  private static final int READ_TIMEOUT_MS    = (int) TimeUnit.MINUTES.toMillis(5);

  public static final String API_BASE_URL = "https://api.cloudflare.com/client/v4";

  public static final int RECORD_ALREADY_EXISTS = 81057;

  private final String             zoneId;
  private final HttpRequestFactory requestFactory;

  public ColudflareApiV4(String zoneId, String token) {
    this.zoneId = zoneId;
    HttpTransport transport = new NetHttpTransport.Builder()
        .setSslSocketFactory(null)
        .setProxy(Proxy.NO_PROXY)
        .setHostnameVerifier(SimpleHostnameVerifier.INSTANCE)
        .build();
    HttpRequestInitializer httpRequestInitializer = request -> request.setInterceptor(r -> r.getHeaders().setAuthorization("Bearer " + token));
    this.requestFactory = transport.createRequestFactory(httpRequestInitializer);
  }

  @Override public DnsRecord createDnsRecord(RecordType type, String recordName, String recordContent)
      throws IOException, CloudflareApiV4Exception {
    Log.debug().log(getClass(), "adding {} record {} = {}, zoneId {}...", type, recordName, recordContent, zoneId);

    CreateDnsRecord request = new CreateDnsRecord();
    request.setType(type);
    request.setName(recordName);
    request.setContent(recordContent);
    request.setTtl(300);

    HttpContent content = new GsonHttpContent(request);

    GenericUrl url = new GenericUrl(API_BASE_URL);
    url.getPathParts().addAll(Arrays.asList("zones", zoneId, "dns_records"));

    CreateDnsRecordResponse response = executeUnparsed(HttpMethod.POST, url, content).parseAs(CreateDnsRecordResponse.class);

    return checkResponse(response, "cannot create DNS record with type " + type + " and name " + recordName);
  }

  @Override public void deleteDnsRecord(RecordType type, String recordName, String recordContent) throws IOException, CloudflareApiV4Exception {
    Log.debug().log(getClass(), "deleting {} record {}, zoneId {}...", type, recordName, zoneId);

    List<DnsRecord> records = listDnsRecords(type, recordName);
    if (records.size() != 1) {
      throw new IllegalStateException(String.format("expected only 1 %s record with name %s but was %s", type, recordName, records.size()));
    }
    DnsRecord record = records.getFirst();

    GenericUrl url = new GenericUrl(API_BASE_URL);
    url.getPathParts().addAll(Arrays.asList("zones", zoneId, "dns_records", record.getId()));

    DeleteDnsRecordResponse response = executeUnparsed(HttpMethod.DELETE, url, null).parseAs(DeleteDnsRecordResponse.class);

    checkResponse(response, "cannot delete DNS record with type" + type + " and name " + recordName);
  }

  @Override public List<DnsRecord> listDnsRecords(RecordType type, String recordName) throws IOException, CloudflareApiV4Exception {
    Log.debug().log(getClass(), "find %s records with name {}, zoneId {}...", type, recordName, zoneId);

    GenericUrl url = new GenericUrl(API_BASE_URL);
    url.getPathParts().addAll(Arrays.asList("zones", zoneId, "dns_records"));
    url.put("type", type.name());
    url.put("name", recordName);

    ListDnsRecordsResponse response = executeUnparsed(HttpMethod.GET, url, null).parseAs(ListDnsRecordsResponse.class);

    return checkResponse(response, "cannot find DNS record with type" + type + " and name " + recordName);
  }

  private <R> R checkResponse(AbstractResponse<R> response, String errorMessage) throws CloudflareApiV4Exception {
    if (!response.isSuccess()) {
      throw new CloudflareApiV4Exception(errorMessage, response.getErrors());
    }
    return response.getResult();
  }

  private HttpResponse executeUnparsed(HttpMethod method, GenericUrl url, HttpContent content) throws IOException {
    HttpRequest httpRequest = switch (method) {
      case GET -> requestFactory.buildGetRequest(url);
      case POST -> requestFactory.buildPostRequest(url, content);
      case DELETE -> requestFactory.buildDeleteRequest(url);
      default -> throw new IllegalArgumentException("unsupported HTTP Method " + method);
    };

    httpRequest.setFollowRedirects(false);
    httpRequest.setThrowExceptionOnExecuteError(false);
    httpRequest.setConnectTimeout(CONNECT_TIMEOUT_MS);
    httpRequest.setReadTimeout(READ_TIMEOUT_MS);

    httpRequest.setParser(new GsonObjectParser());

    HttpResponse httpResponse = httpRequest.execute();
    if (httpResponse.getContentType().contains("application/json")) {
      return httpResponse;
    }
    throw httpResponseException(httpResponse);
  }

  private HttpResponseException httpResponseException(HttpResponse response) {
    var builder = new HttpResponseException.Builder(response.getStatusCode(), response.getStatusMessage(), response.getHeaders());
    builder.setMessage(response.getStatusMessage());
    String content = null;
    try {
      content = response.parseAsString();
    } catch (IOException ex) {
      Log.warn().log(getClass(), "cannot parse response content", ex);
    }
    builder.setContent(content);
    return builder.build();
  }
}
