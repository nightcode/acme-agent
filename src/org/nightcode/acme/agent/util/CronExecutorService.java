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

import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.model.time.ExecutionTime;
import com.cronutils.parser.CronParser;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jetbrains.annotations.NotNull;
import org.nightcode.common.logging.Log;
import org.nightcode.common.util.ExecutorUtils;

import static java.time.ZoneOffset.UTC;

public class CronExecutorService implements Executor {

  private final String          name;
  private final CronParser      cronParser;
  private final ExecutorService virtualExecutor;

  private final AtomicBoolean isRunning = new AtomicBoolean(true);

  public CronExecutorService(String name) {
    this(name, CronType.UNIX.name());
  }

  public CronExecutorService(String name, String cronType) {
    this.name            = name;
    this.cronParser      = new CronParser(CronDefinitionBuilder.instanceDefinitionFor(CronType.valueOf(cronType)));
    this.virtualExecutor = Executors.newVirtualThreadPerTaskExecutor();
  }

  @Override public void execute(@NotNull Runnable command) {
    command.run();
  }

  public void schedule(String jobName, Runnable task, String expression) {
    if (!isRunning.get()) {
      throw new IllegalStateException("scheduler has been shut down, cannot accept new cron jobs");
    }

    var parsedCron    = cronParser.parse(expression);
    var executionTime = ExecutionTime.forCron(parsedCron);

    Thread.startVirtualThread(() -> {
      while (isRunning.get() && !Thread.currentThread().isInterrupted()) {
        try {
          var now        = ZonedDateTime.now(UTC);
          var nextRunOpt = executionTime.nextExecution(now);

          if (nextRunOpt.isEmpty()) {
            break;
          }

          var nextRun    = nextRunOpt.get();
          var timeToWait = Duration.between(now, nextRun);

          if (timeToWait.isNegative() || timeToWait.isZero()) {
            continue;
          }
          Thread.sleep(timeToWait);

          if (isRunning.get()) {
            virtualExecutor.submit(() -> execute(task));
          }
        } catch (InterruptedException ex) {
          Log.info().log(CronExecutorService.class, "master loop for job '{}' with cron '{}' interrupted and closed", jobName, expression);
          Thread.currentThread().interrupt();
        } catch (Exception ex) {
          Log.error().log(CronExecutorService.class, ex, "critical failure inside loop configuration for job '{}' with cron '{}'", jobName, expression);
        }
      }
    });
  }

  public boolean shutdown() {
    return shutdownGracefully(60, TimeUnit.SECONDS);
  }

  public boolean shutdownGracefully(long duration, TimeUnit unit) {
    if (!isRunning.compareAndSet(true, false)) {
      return true;
    }

    Log.info().log(getClass(), "[{}] shutting down..", name);
    virtualExecutor.shutdown();

    try {
      long    timeoutNanos  = TimeUnit.SECONDS.toNanos(10);
      long    durationNanos = unit.toNanos(duration);
      long    iterations    = durationNanos / timeoutNanos;
      boolean terminated    = false;

      for (int i = 0; i < iterations && !terminated; i++) {
        terminated = virtualExecutor.awaitTermination(timeoutNanos, TimeUnit.NANOSECONDS);
        if (!terminated) {
          Log.info().log(ExecutorUtils.class, "[{}] the timeout elapsed before termination, iteration {} of {}", name, i + 1, iterations);
        }
      }
      if (!virtualExecutor.isTerminated()) {
        Log.warn().log(ExecutorUtils.class, "[{}] graceful window expired, enforcing absolute termination on hanging jobs", name);
        List<Runnable> neverCommencedExecution = virtualExecutor.shutdownNow();
        for (Runnable r : neverCommencedExecution) {
          Log.warn().log(ExecutorUtils.class, "[{}] shutdown now {}", name, r);
        }
      } else {
        Log.info().log(CronExecutorService.class, "[{}] terminated", name);
      }
    } catch (InterruptedException ex) {
      Log.warn().log(CronExecutorService.class, ex, "[{}] termination sequence violently interrupted", name);
      virtualExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }
    return virtualExecutor.isTerminated();
  }
}
