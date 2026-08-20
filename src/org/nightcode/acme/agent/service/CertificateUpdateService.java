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

package org.nightcode.acme.agent.service;

import org.nightcode.acme.agent.ServerConfig;
import org.nightcode.acme.agent.job.CertificatesUpdateJob;
import org.nightcode.acme.agent.service.acme.AcmeService;
import org.nightcode.acme.agent.util.CronExecutorService;
import org.nightcode.common.logging.Log;
import org.nightcode.common.service.AbstractService;

public class CertificateUpdateService extends AbstractService {

  private final ServerConfig          config;
  private final CronExecutorService   cronExecutor;
  private final CertificatesUpdateJob job;

  public CertificateUpdateService(ServerConfig config, AcmeService acmeService) {
    this.config       = config;
    this.cronExecutor = new CronExecutorService(getClass().getSimpleName() + "Cron");

    this.job = new CertificatesUpdateJob(config, acmeService);
    this.job.executeInternal();
  }

  @Override protected void doStart() {
    try {
      String jobName        = job.getJobName();
      String cronExpression = config.getCertificatesUpdateJobCron();
      if (cronExpression == null) {
        throw new IllegalStateException("can not find cron expression for CertificatesUpdateJob");
      }

      cronExecutor.schedule(jobName, job, cronExpression);
      Log.info().log(getClass(), "registered job '{}' with cron expression '{}'", jobName, cronExpression);

      notifyStarted();
    } catch (Exception ex) {
      notifyFailed(ex);
    }
  }

  @Override protected void doStop() {
    try {
      cronExecutor.shutdown();
      notifyStopped();
    } catch (Exception ex) {
      notifyFailed(ex);
    }
  }
}
