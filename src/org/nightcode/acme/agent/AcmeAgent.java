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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter;
import io.opentelemetry.sdk.logs.export.LogRecordExporter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.nightcode.common.config.ConfigLoader;
import org.nightcode.common.service.ServiceBootstrap;

public final class AcmeAgent {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  public static void main(String[] args) {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: acme-agent <config-file>");
    }
    Path configPath = Paths.get(args[0]).toAbsolutePath();
    if (!Files.isReadable(configPath)) {
      throw new IllegalArgumentException("config file is not readable: " + configPath);
    }
    ServerConfig serverConfig = ConfigLoader.yaml().loadConfig(ServerConfig.class, () -> Files.newBufferedReader(configPath));

    LogRecordExporter logRecordExporter = null;
    if (serverConfig.getOtelCollectorEndpoint() != null && !serverConfig.getOtelCollectorEndpoint().isEmpty()) {
       logRecordExporter = OtlpGrpcLogRecordExporter
          .builder()
          .setEndpoint(serverConfig.getOtelCollectorEndpoint())
          .setTimeout(10_000, TimeUnit.MILLISECONDS)
          .build();
    }

    new ServiceBootstrap<ServerConfig>("org.nightcode", "acme-agent")
        .config(() -> serverConfig)
        .logRecordExporter(logRecordExporter)
        .initializer((config, context) -> {
          ServiceFactory factory = new ServiceFactory(config, context);
          factory.certificateUpdateService().startAsync().get();
        })
        .start();
  }

  private AcmeAgent() {
    // do nothing
  }
}
