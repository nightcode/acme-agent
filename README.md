# ACME-agent

[![Build Status](https://github.com/nightcode/acme-agent/actions/workflows/maven.yml/badge.svg)](https://github.com/nightcode/acme-agent/actions/workflows/maven.yml)
[![GitHub license](https://img.shields.io/github/license/nightcode/acme-agent.svg)](https://github.com/nightcode/acme-agent/blob/main/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/org.nightcode/acme-agent.svg)](http://search.maven.org/#search%7Cga%7C1%7Cg%3Aorg.nightcode%20a%3Aacme-agent)

ACME-agent.

#### Available options

| Name                                                         | Possible values        | Default value     |
|--------------------------------------------------------------|------------------------|-------------------|
| org.nightcode.config.useEnv                                  | true, false            | true              |
| org.nightcode.opentelemetry.service.name                     | string                 | pid: {pid}        |
| org.nightcode.opentelemetry.service.version                  | string                 | unknown           |
| org.nightcode.logging.opentelemetry.disable                  | true, false            | false             |
| org.nightcode.logging.opentelemetry.batch.maxQueueSize       | [0, Integer.MAX_VALUE] | 2048              |
| org.nightcode.logging.opentelemetry.batch.maxExportBatchSize | [0, Integer.MAX_VALUE] | 512               |
| org.nightcode.logging.opentelemetry.batch.scheduleDelayMs    | [0, Long.MAX_VALUE]    | 5000              |
| org.nightcode.logging.opentelemetry.batch.exporterTimeoutMs  | [0, Long.MAX_VALUE]    | 30000             |


Download
--------

Download [the latest jar][1] via Maven:
```xml
<dependency>
  <groupId>org.nightcode</groupId>
  <artifactId>acme-agent</artifactId>
  <version>0.2.1</version>
</dependency>
```

Feedback is welcome. Please don't hesitate to open up a new [github issue](https://github.com/nightcode/acme-agent/issues) or simply drop me a line at <dmitry@nightcode.org>.


[1]: http://oss.sonatype.org/service/local/artifact/maven/redirect?r=releases&g=org.nightcode&a=acme-agent&v=LATEST
