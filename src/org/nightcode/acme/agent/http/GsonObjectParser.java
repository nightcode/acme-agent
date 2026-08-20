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

package org.nightcode.acme.agent.http;

import com.google.api.client.util.ObjectParser;
import com.google.gson.Gson;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.charset.Charset;

public class GsonObjectParser implements ObjectParser {

  private final Gson gson;

  public GsonObjectParser() {
    gson = new Gson();
  }

  public GsonObjectParser(Gson gson) {
    this.gson = gson;
  }

  @Override public <T> T parseAndClose(InputStream in, Charset charset, Class<T> dataClass) throws IOException {
    InputStreamReader reader = new InputStreamReader(in, charset);
    return parseAndClose(reader, dataClass);
  }

  @Override public Object parseAndClose(InputStream in, Charset charset, Type dataType) throws IOException {
    InputStreamReader reader = new InputStreamReader(in, charset);
    return parseAndClose(reader, dataType);
  }

  @Override public <T> T parseAndClose(Reader reader, Class<T> dataClass) throws IOException {
    return gson.fromJson(reader, dataClass);
  }

  @Override public Object parseAndClose(Reader reader, Type dataType) throws IOException {
    return gson.fromJson(reader, dataType);
  }
}
