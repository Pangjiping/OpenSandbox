# Egress OpenTelemetry metrics and logging

This document describes **OpenTelemetry Metrics** and **structured logs / OTLP Logs** implemented in the **OpenSandbox
Egress** sidecar (aligned with [OSEP-0010](../../../oseps/0010-opentelemetry-instrumentation.md)). **Distributed tracing
is not implemented** (no `trace_id` / `span_id`).

Entry points:

- Shared OTLP bootstrap: `components/internal/telemetry`
- Egress-specific metrics and wiring: `components/egress/pkg/telemetry`

---

## Enabling OTLP export

Export is controlled by **`internal/telemetry.Init`** from environment variables. If **no OTLP endpoint is configured**,
no OTLP connection is opened and runtime behavior matches a build without observability.

### Enabling each signal

| Signal                | Condition                                                                                                           |
|-----------------------|---------------------------------------------------------------------------------------------------------------------|
| **Metrics**           | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` **or** `OTEL_EXPORTER_OTLP_ENDPOINT` is non-empty (after `strings.TrimSpace`) |
| **Logs (zap → OTLP)** | `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` **or** `OTEL_EXPORTER_OTLP_ENDPOINT` is non-empty                                |

They can be enabled independently: metrics-only endpoint exports metrics only; logs-only endpoint attaches OTLP for logs
and **tees** them with stdout JSON.

### Common environment variables

| Variable                              | Description                                                                                                             |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`         | Shared OTLP HTTP base URL (e.g. `http://otel-collector:4318`). Used when metrics/logs endpoints are not set separately. |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Metrics only; if set, it **takes precedence** over the shared endpoint.                                                 |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`    | Logs only; if set, it **takes precedence** over the shared endpoint.                                                    |
| `OPENSANDBOX_EGRESS_SANDBOX_ID`       | Optional. When non-empty, sets the **`osbx.id`** field on the Resource and in structured logs.                          |

Other OTLP HTTP exporter behavior (protocol, headers, timeout, compression, etc.) follows the **OpenTelemetry Go SDK**
conventions for `OTEL_EXPORTER_OTLP_*`;
see [SDK environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

Variables **not read** by this implementation include: `OTEL_METRICS_EXPORTER`, `OTEL_LOGS_EXPORTER`,
`OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`. Egress uses a **fixed** `service.name` (see table below).

### Local log level

Structured logs and OTLP share the same zap pipeline. **`OPENSANDBOX_EGRESS_LOG_LEVEL`** (e.g. `info` / `warn`) controls
which levels are emitted; levels filtered out are not sent to OTLP either.

---

## Resource attributes

When exporting metrics and logs, the Resource includes at least:

| Attribute      | Value                                                                        |
|----------------|------------------------------------------------------------------------------|
| `service.name` | Fixed **`opensandbox-egress`**                                               |
| `osbx.id`      | Set when **`OPENSANDBOX_EGRESS_SANDBOX_ID`** is non-empty; otherwise omitted |

---

## Metrics reference

Meter name: `opensandbox/egress`. Instrument names and behavior:

| Name                               | Type             | Unit / notes | When it fires                                                                                                                                                                                                       |
|------------------------------------|------------------|--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `egress.dns.query.duration`        | Histogram        | `s`          | After an upstream **forward** when the policy **allows** the query; records duration in seconds for both **success** and **forward error**. Policy **deny** does not perform a forward, so **no** histogram sample. |
| `egress.policy.denied_total`       | Counter          | —            | Incremented by **1** when a DNS query is **denied** by policy.                                                                                                                                                      |
| `egress.nftables.updates.count`    | Counter          | —            | Incremented by **1** after each successful **`nftables.Manager.ApplyStatic`** (including successful retry without delete-table) or successful **`AddResolvedIPs`**.                                                 |
| `egress.nftables.rules.count`      | Observable Gauge | `{element}`  | **Approximate** policy size after the last successful static apply, updated via `NftRuleCountFromPolicy` (egress rule count + static allow/deny set element counts).                                                |
| `egress.system.memory.usage_bytes` | Observable Gauge | `By`         | **System** RAM in use (Linux: **MemTotal − MemAvailable** from `/proc/meminfo`; fallback **MemTotal − MemFree**; non-Linux: **0**).                                                                                 |
| `egress.system.cpu.utilization`    | Observable Gauge | `1`          | **CPU busy ratio** (0–1) since last scrape: non-idle jiffies / total jiffies on the aggregate `cpu` line in `/proc/stat` (Linux). **First** scrape after start is **0** (no prior sample). Non-Linux: **0**.          |

If OTLP metrics are **not** enabled (no endpoint), these instruments are not registered and `Record*` calls are no-ops.

---

## Structured logs reference

All logs below go through **zap**. When OTLP logs are enabled, the **same fields** are sent to OTLP via **otelzap**. The
**`osbx.*`** prefix matches OSEP.

### Outbound access (DNS path)

| Field         | Description                                                                            |
|---------------|----------------------------------------------------------------------------------------|
| `osbx.event`  | Always **`egress.outbound`**                                                           |
| `osbx.result` | `allow` \| `error` (policy **deny** does not emit this log)                             |
| `osbx.id`     | From `OPENSANDBOX_EGRESS_SANDBOX_ID` when set                                          |
| `osbx.host`   | Normalized QNAME (lowercase, trailing dot stripped); name-based queries                |
| `osbx.ips`    | Resolved IPv4/IPv6 strings when allowed and A/AAAA records exist                       |
| `osbx.peer`   | Reserved for IP-only paths; the DNS proxy path primarily uses `osbx.host` / `osbx.ips` |
| `osbx.err`    | Short error when `osbx.result` is `error`                                              |

**Instrumentation:** `components/egress/pkg/dnsproxy/proxy.go` (`serveDNS`: allow / forward error only; deny uses metrics + optional webhook, no structured outbound log).

**Level:** `info` (forward failures also emit the existing `Warnf` line).

### Policy lifecycle

| `osbx.event`           | Level        | Description                                                                                       |
|------------------------|--------------|---------------------------------------------------------------------------------------------------|
| `egress.loaded`        | info         | After the **initial policy** is loaded at startup                                                 |
| `egress.updated`       | info         | After a successful **`POST`/`PUT`/`PATCH` `/policy`** or **empty-body reset**                     |
| `egress.update_failed` | warn / error | Validation failures, persist failures, nft apply failures, etc. (warn vs error reflects severity) |

**Common fields:** `osbx.src` (e.g. `policy_file` / `env` / `default` / `http`), `osbx.default`, `osbx.rule_count`,
`osbx.rules` (rule summary array), `osbx.err` on failure.

**Instrumentation:** `components/egress/policy_utils.go` (`logEgressLoaded`, etc.), `components/egress/main.go` (
`logEgressLoaded` at startup), `components/egress/policy_server.go` (success and failure paths).

---

## Source code quick reference

| Topic                                    | Path                                                                                   |
|------------------------------------------|----------------------------------------------------------------------------------------|
| Shared `Init`                            | `components/internal/telemetry/init.go`                                                |
| Egress bootstrap                         | `components/egress/pkg/telemetry/init.go`                                              |
| Egress metric registration and `Record*` | `components/egress/pkg/telemetry/metrics.go`                                           |
| Zap tee (stdout + OTLP core)             | `components/internal/logger/zap.go` (`NewWithExtraCores`), `components/egress/main.go` |
