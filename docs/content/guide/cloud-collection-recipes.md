# Cloud Collection Recipes

{{ added "0.20.0" }}

This page shows how common log shippers, such as Vector, OpenTelemetry (OTel), and Grafana Alloy, deliver CloudTrail, Azure, GCP, M365, GitHub, Okta, OneLogin, Kubernetes audit, Docker, and osquery events in a structured JSON shape that [schema classification](../reference/schema-signatures.md) recognizes automatically, and which routing binding to use when a schema needs a field-mapping pipeline.

All examples target `rsigma engine daemon` with `--schema-routing`. Each recipe maps to one of the built-in schemas defined in [Schema Signatures](../reference/schema-signatures.md); no user-defined `schemas:` block is needed because every source ships as a built-in. Use `--schema-config` when you need a `routing:` section (per-schema pipeline bindings, `on_unknown`, or `default_pipelines`).

Vector examples POST JSON to `/api/v1/events` (`--input http`). OpenTelemetry Collector and Grafana Alloy examples use OTLP HTTP (`/v1/logs`); build or install the daemon with `daemon-otlp` (release archives already include it). OTLP is active whenever that feature is compiled in, regardless of `--input`. See [OTLP Integration](otlp-integration.md) for the LogRecord mapping and TLS variants.

## Built-in schemas (quick reference)

| Schema | Signature name | Implied logsource |
|--------|---------------|-------------------|
| AWS CloudTrail | `aws_cloudtrail` | `aws / cloudtrail` |
| AWS VPC Flow Logs (JSON) | `aws_vpcflow` | `aws` + custom `{source: vpcflow}` |
| Azure Activity Logs | `azure_activitylogs` | `azure / activitylogs` |
| Azure Audit Logs | `azure_auditlogs` | `azure / auditlogs` |
| Azure SignIn Logs | `azure_signinlogs` | `azure / signinlogs` |
| GCP Cloud Audit | `gcp_audit` | `gcp / gcp.audit` |
| Microsoft 365 unified audit log | `m365_audit` | `m365 / audit` |
| GitHub Audit | `github_audit` | `github / audit` |
| Okta System Log | `okta_system_log` | `okta / okta` |
| OneLogin | `onelogin_events` | `onelogin / onelogin.events` |
| Kubernetes Audit | `k8s_audit` | custom `{platform: kubernetes, source: k8s.audit}` |
| Docker Events | `docker_events` | custom `{platform: docker, source: docker.events}` |
| osquery Result | `osquery_result` | custom `{platform: osquery, source: osquery.result}` |

## AWS CloudTrail

CloudTrail delivers JSON events with `eventVersion`, `eventSource`, `userIdentity`, and `eventID`, the four marker fields. Shippers just need to deliver the native JSON form.

::: tabs

== tab "Vector"
```toml
[sources.cloudtrail]
type = aws_s3
acknowledgements.enabled = false
bucket.name = "cloudtrail-bucket"
bucket.region = "us-east-1"
format = {type = "ndjson", parse_from = "s3_key"}

[sinks.rsigma]
inputs = ["cloudtrail"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
No native CloudTrail OTel collector; ship via the generic `file` input reading from the S3-retrieved JSON:

```yaml
receivers:
  filelog:
    include: [/var/log/cloudtrail/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "cloudtrail" {
    include  = ["/var/log/cloudtrail/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

Start Alloy with `--stability.level=public-preview` when using `otelcol.receiver.filelog`.

:::

## Azure Event Hubs / Management Activity API

Azure emits JSON with a `category` field that determines the service (`activitylogs`, `signinlogs`, `auditlogs`). Shippers need only deliver each category as-is; the built-in schema classifier picks the right service from the `category` value.

::: tabs

== tab "Vector"
```toml
[sources.azure_signin]
type = azure_event_hubs
connection_string = "<connection-string>"
topic = "insights-operationallogs"
partition_endpoint = "2021-04-01"

[sinks.rsigma]
inputs = ["azure_signin"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  azureeventhub:
    connection_string: "<connection-string>"
    storage: file_storage
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [azureeventhub]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
No native Azure Event Hubs to OTLP component; read Event Hub-exported JSON from disk (or a puller that writes NDJSON) and forward:

```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "azure" {
    include  = ["/var/log/azure/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## GCP Cloud Audit Logs

GCP Cloud Audit logs are `LogEntry` objects whose `protoPayload.@type` equals `type.googleapis.com/google.cloud.audit.AuditLog`. The built-in signature matches on the `@type` value alone (specificity 95).

SigmaHQ's `gcp.audit` rules reference fields under a `data.` prefix (for example `data.protoPayload.serviceName`), while a native Cloud Logging event carries them without it (`protoPayload.serviceName`). Use the builtin `gcp_audit` pipeline to strip the `data.` prefix from rule field names so those rules match native events.

For a GCP-only feed, apply the pipeline globally (schema routing is optional):

```bash
rsigma engine daemon -r rules/ -p gcp_audit --input http --api-addr 0.0.0.0:8952
```

On a mixed stream with `--schema-routing`, bind the pipeline to the `gcp_audit` schema in `--schema-config` instead of relying on `-p` alone (see [A combined example](#a-combined-example)). With schema routing enabled and no bindings, every event falls through to `default_pipelines`, and a bare `-p` is not applied per schema.

::: tabs

== tab "Vector"
```toml
[sources.gcp_audit]
type = http_server
address = "0.0.0.0:9001"
method = POST
allowed_sources = ["127.0.0.1"]

[sinks.rsigma]
inputs = ["gcp_audit"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/gcp-audit/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "gcp_audit" {
    include  = ["/var/log/gcp-audit/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## Microsoft 365 / Entra

The Office 365 Management Activity API emits unified audit log events with the common-schema fields `RecordType`, `Operation`, `CreationTime`, `Workload`, and `OrganizationId`. The classifier recognizes this raw shape (any `Workload`) as `m365_audit` and maps it to `product: m365, service: audit`, where SigmaHQ's native-field rules live.

SigmaHQ's `exchange`, `threat_detection`, and `threat_management` services are written against a separately normalized shape (`eventSource`, `eventName`, `status`), which are not Management Activity common-schema fields. RSigma does not ship a normalization pipeline for that shape, so raw Management Activity events are not classified into those services.

::: tabs

== tab "Vector"
```toml
[sources.m365]
type = http_server
address = "0.0.0.0:9002"

[sinks.rsigma]
inputs = ["m365"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/m365/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "m365" {
    include  = ["/var/log/m365/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## GitHub Audit Log

The GitHub Audit Log API returns JSON with `action`, `actor`, `org`/`repo`, `created_at`, and `_document_id`.

::: tabs

== tab "Vector"
```toml
[sources.github]
type = http_server
address = "0.0.0.0:9003"

[sinks.rsigma]
inputs = ["github"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/github-audit/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "github" {
    include  = ["/var/log/github-audit/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## Okta System Log

Okta System Log API events carry `eventType`, `actor`, `outcome.result`, and `published`.

::: tabs

== tab "Vector"
```toml
[sources.okta]
type = http_server
address = "0.0.0.0:9004"

[sinks.rsigma]
inputs = ["okta"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/okta/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "okta" {
    include  = ["/var/log/okta/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## OneLogin Events API

OneLogin Events API records carry `event_type_id`, `account_id`, `created_at`, and `user_id`/`actor_user_id`.

::: tabs

== tab "Vector"
```toml
[sources.onelogin]
type = http_server
address = "0.0.0.0:9005"

[sinks.rsigma]
inputs = ["onelogin"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/onelogin/*.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "onelogin" {
    include  = ["/var/log/onelogin/*.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## Kubernetes Audit Log

Kubernetes audit events have `kind: Event`, `apiVersion: audit.k8s.io/`, `auditID`, `verb`, and `user.username`.

::: tabs

== tab "Vector"
### Option A: kube-apiserver sink

The kube-apiserver has a built-in audit webhook that forwards events in JSON. Forward to a Vector HTTP listener:

```toml
[sources.k8s]
type = http_server
address = "0.0.0.0:9006"

[sinks.rsigma]
inputs = ["k8s"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

### Option B: audit log file

Forward the audit log JSON file with a tailing file input:

```toml
[sources.k8s]
type = file
include = ["/var/log/kubernetes/audit.log"]
read_from = beginning
encoding = "ndjson"

[sinks.rsigma]
inputs = ["k8s"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/kubernetes/audit.log]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "k8s" {
    include  = ["/var/log/kubernetes/audit.log"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## Docker Events

Docker events (`docker events --format json` or the API `events` endpoint) carry `Type`, `Action`, and `Actor`. The `docker_events` signature (specificity 70) uses these fields for recognition.

::: tabs

== tab "Vector"
```toml
[sources.docker]
type = docker_events
format = pretty

[sinks.rsigma]
inputs = ["docker"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

The native `docker` input (which taps into the Docker Engine API directly) may not capture all events the CLI `--format json` form does. Use the Docker Engine API's `/events` endpoint via `curl` or a dedicated library for full coverage.

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/docker/events.json]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

Pipe `docker events --format json` into the file, or use a small sidecar that writes the Engine API `/events` stream as NDJSON.

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "docker" {
    include  = ["/var/log/docker/events.json"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## osquery

osquery sends result lines (one JSON per table query) to configured log destinations. Each result carries `name`, `action` (added/removed/snapshot), `hostIdentifier`, and `columns`.

::: tabs

== tab "Vector"
```toml
[sources.osquery]
type = file
include = ["/var/log/osquery/*.log"]
read_from = beginning

[sinks.rsigma]
inputs = ["osquery"]
type = http
uri = "http://localhost:8952/api/v1/events"
encoding.codec = json
```

== tab "OpenTelemetry"
```yaml
receivers:
  filelog:
    include: [/var/log/osquery/*.log]
    operators:
      - type: json_parser
        parse_to: body
processors:
  batch: {}
exporters:
  otlphttp/rsigma:
    endpoint: "http://localhost:8952"
    compression: none
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/rsigma]
```

== tab "Alloy"
```alloy
otelcol.exporter.otlphttp "rsigma" {
    client {
        endpoint = "http://localhost:8952"
    }
}

otelcol.receiver.filelog "osquery" {
    include  = ["/var/log/osquery/*.log"]
    start_at = "beginning"

    operators = [{
        type     = "json_parser",
        parse_to = "body",
    }]

    output {
        logs = [otelcol.exporter.otlphttp.rsigma.input]
    }
}
```

:::

## A combined example

One daemon that accepts Vector on `/api/v1/events` and OTLP agents on `/v1/logs`, with schema routing and the GCP pipeline binding:

```yaml
# /etc/rsigma/rsigma.yaml
version: 1

daemon:
  rules: /etc/rsigma/rules
  api:
    addr: "0.0.0.0:8952"
  input:
    source: http
  output:
    sinks: [stdout]
  schema:
    routing: true
    config: /etc/rsigma/schema-routing.yml
```

```bash
rsigma engine daemon --config /etc/rsigma/rsigma.yaml
```

`schema-routing.yml`:

```yaml
routing:
  on_unknown: warn
  default_pipelines: []
  bindings:
    # GCP AuditLog needs the field-mapping pipeline; other cloud schemas match native fields with an empty pipeline-set.
    - schema: gcp_audit
      pipelines: [gcp_audit]
```

No `schemas:` entries are needed. Every Cloud, SaaS, and Container source in this guide ships as a built-in. The only binding required is the `gcp_audit` pipeline mapping (since SigmaHQ rules expect `data.*` field names, not native `protoPayload.*`). Built-in implied logsources already supply the SigmaHQ `product`/`service` tokens for pruning when [logsource routing](logsource-routing.md) is also enabled.

## See also

- [Schema Routing](schema-routing.md) for bindings, aliases, and schema-derived logsource pruning.
- [Schema Signatures](../reference/schema-signatures.md) for the built-in catalog and signature grammar.
- [OTLP Integration](otlp-integration.md) for `/v1/logs`, LogRecord flattening, and agent recipes.
- [HTTP API](../reference/http-api.md) for `POST /api/v1/events`.
- [Configuration](../reference/configuration.md) for the `daemon.schema` config block.
- [Streaming Detection](streaming-detection.md) for daemon lifecycle and inputs.
