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

package org.nightcode.acme.agent.job;

import org.nightcode.common.logging.Log;

public abstract class CronJob implements Runnable {

  private final String jobName;

  public CronJob() {
    this.jobName = this.getClass().getSimpleName();
  }

  @Override public void run() {
    Log.info().log(getClass(), "executing job: " + jobName);
    try {
      executeInternal();
    } catch (Exception ex) {
      Log.warn().log(getClass(), ex, "job: {} has failed", jobName);
    }
  }

  public String getJobName() {
    return this.jobName;
  }

  public abstract void executeInternal();
}
