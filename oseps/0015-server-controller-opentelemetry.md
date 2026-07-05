---
title: OpenTelemetry Metrics and Traces for Server and Controller
authors:
  - "@Pangjiping"
creation-date: 2026-07-05
last-updated: 2026-07-05
status: provisional
---

# OSEP-0015: OpenTelemetry Metrics and Traces for Server and Controller

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Requirements](#requirements)
- [Proposal](#proposal)
  - [Notes/Constraints/Caveats](#notesconstraintscaveats)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [1. Metrics](#1-metrics)
    - [1.1 Server metrics (Python / FastAPI)](#11-server-metrics-python--fastapi)
    - [1.2 Controller metrics (Go / controller-runtime)](#12-controller-metrics-go--controller-runtime)
  - [2. Distributed Tracing](#2-distributed-tracing)
    - [2.1 Correlation model](#21-correlation-model)
    - [2.2 Server spans](#22-server-spans)
    - [2.3 Controller spans](#23-controller-spans)
    - [2.4 Correlation with OSEP-0010 components](#24-correlation-with-osep-0010-components)
  - [3. Initialization and configuration](#3-initialization-and-configuration)
    - [3.1 Server (Python)](#31-server-python)
    - [3.2 Controller (Go)](#32-controller-go)
- [Test Plan](#test-plan)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Infrastructure Needed](#infrastructure-needed)
- [Upgrade & Migration Strategy](#upgrade--migration-strategy)
<!-- /toc -->

## Summary

This proposal introduces OpenTelemetry **Metrics** and **Distributed Tracing** for the OpenSandbox **server** (Python/FastAPI) and **controller** (Go/controller-runtime). It extends [OSEP-0010](./0010-opentelemetry-instrumentation.md) (which covers execd, egress, and ingress with metrics+logs only, explicitly excluding tracing). Server and controller each emit independent traces; cross-component correlation relies on the shared **`sandbox_id`** attribute rather than trace context propagation.

## Motivation

Today's observability covers the data-plane components (execd, egress, ingress) via OSEP-0010, but the control-plane path—user request → server → K8s API → controller → Pod lifecycle—has no unified instrumentation:

- **Server**: No standardized HTTP request metrics (beyond logging). No trace context to follow a `POST /sandboxes` through to the Pod becoming ready.
- **Controller**: Uses controller-runtime's built-in Prometheus metrics (workqueue depth, reconcile duration) but lacks OpenTelemetry format export, custom business metrics (allocation latency, pool hit rates), and tracing that links back to the originating API request.

Without cross-component tracing, diagnosing latency (e.g. "why did sandbox creation take 8s?") requires manual timestamp correlation across server logs, K8s events, and controller logs.

### Goals

- Instrument the **server** with OpenTelemetry metrics (HTTP, sandbox lifecycle, pool operations) and traces (per-request spans).
- Instrument the **controller** with OpenTelemetry metrics (reconcile operations, allocation, pool scaling) and traces (per-reconcile spans).
- Provide a shared `sandbox_id` attribute across server traces, controller traces, and OSEP-0010 metrics/logs for cross-component correlation (query by `sandbox_id` in the trace backend to find related traces across services).
- Support OTLP export with env-var configuration; default to no-export (noop) for deployments without observability backends.

### Non-Goals

- Replacing controller-runtime's built-in Prometheus `/metrics` endpoint — coexist additively.
- Instrumenting execd/egress/ingress with tracing — those remain metrics+logs per OSEP-0010. Traces reaching those components is a future extension.
- Mandating a specific trace backend (Jaeger, Tempo, etc.) — export is via standard OTLP only.
- Adding OpenTelemetry Logs to server or controller — use existing structured logging (Python `logging` with `request_id`; controller-runtime `logr`).

## Requirements

| ID | Requirement | Priority |
|----|-------------|----------|
| R1 | Server exports HTTP and business metrics via OTLP | Must Have |
| R2 | Controller exports custom business metrics (pool, sandbox, snapshot) via OTLP; built-in controller-runtime Prometheus metrics remain unchanged | Must Have |
| R3 | Server creates trace spans for inbound HTTP requests and outbound K8s API calls | Must Have |
| R4 | Controller creates trace spans for reconcile loops | Must Have |
| R5 | All trace spans include `sandbox_id` where applicable, enabling cross-component queries; metrics use only low-cardinality aggregated dimensions (do NOT use `sandbox_id` as a metric label) | Must Have |
| R6 | Default config (OTLP unset) produces no export and no errors | Must Have |
| R7 | Traces include key attributes (pool name, sandbox count, operation type) for filtering | Should Have |

## Proposal

### Architecture overview

```
User → [Server (FastAPI)] → [Kubernetes API] → [Controller (reconcile)]
            │                                            │
         spans+metrics                              spans+metrics
         (OTLP)                                     (OTLP)
            │                                            │
            └──────── sandbox_id (shared attribute) ─────┘
```

The server and controller do not communicate directly — they interact through the Kubernetes API (CRD objects). Each component emits **independent traces** to the OTLP backend. Cross-component correlation is achieved by querying the shared `sandbox_id` attribute in the trace backend (e.g. Grafana Tempo: `{.sandbox_id = "sb-xxx"}`), which returns traces from both server and controller for that sandbox.

This approach is lightweight and requires no CRD schema changes or annotation injection.

### Notes/Constraints/Caveats

- **Python OpenTelemetry SDK** must be compatible with the project's Python version (≥3.10 per `pyproject.toml`).
- **Controller-runtime** already exposes Prometheus metrics via `metricsserver`; OpenTelemetry metrics are additive and can coexist or replace depending on deployment preference.
- `sandbox_id` on the server side is generated at creation time; on the controller side it is derived from the CRD object name or a label.
- Server and controller traces are **not linked** via `trace_id` — they are independent traces correlated by `sandbox_id`. This means no single "trace waterfall" view across both components; instead, the backend shows two traces that can be navigated by the shared attribute.

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| High-cardinality metric dimensions | `sandbox_id` is used only on trace span attributes (unbounded by nature), never on metric label sets; metrics use aggregated dimensions (operation, status, pool_name) |
| OTLP export failures block request path | Use async/batch exporters with bounded queues; drop on overflow |
| Python auto-instrumentation overhead on FastAPI hot path | Use manual instrumentation for critical spans; benchmark before enabling auto-instrumentation middleware |
| No single trace waterfall across server + controller | Acceptable tradeoff for simplicity; `sandbox_id` attribute query provides equivalent debugging capability without CRD annotation coupling |

## Design Details

### 1. Metrics

#### 1.1 Server metrics (Python / FastAPI)

| Category | Metric name | Type | Description |
|----------|-------------|------|-------------|
| **HTTP** | `server.http.request.duration` | Histogram | Request latency by `http.method`, `http.route`, `http.status_code` |
| **HTTP** | `server.http.request.active` | UpDownCounter | Currently in-flight requests |
| **Sandbox lifecycle** | `server.sandbox.create.duration` | Histogram | End-to-end sandbox creation latency (API received → sandbox ready) by `runtime_type` (`docker`/`kubernetes`), `result` (`success`/`error`) |
| **Sandbox lifecycle** | `server.sandbox.create.total` | Counter | Sandbox creations by `runtime_type`, `result` |
| **Sandbox lifecycle** | `server.sandbox.delete.total` | Counter | Sandbox deletions by `runtime_type`, `result` |
| **Pool** | `server.pool.allocate.duration` | Histogram | Time from pool allocation request to sandbox assigned, by `pool_name`, `result` |
| **Pool** | `server.pool.allocate.total` | Counter | Pool allocation attempts by `pool_name`, `result` (`hit`/`miss`/`error`) |
| **Snapshot** | `server.snapshot.create.duration` | Histogram | Snapshot creation latency by `result` |
| **Snapshot** | `server.snapshot.create.total` | Counter | Snapshot creations by `result` |
| **K8s client** | `server.k8s.request.duration` | Histogram | Outbound K8s API call latency by `verb` (`create`/`get`/`list`/`patch`/`delete`), `resource`, `status_code` |

Meter name: **`opensandbox/server`**.

HTTP metrics use route templates (e.g. `/sandboxes/{sandbox_id}`) not raw paths, following the same cardinality principle as OSEP-0010 §1.1.

#### 1.2 Controller metrics (Go / controller-runtime)

**Built-in metrics (controller-runtime, unchanged):** The controller already exposes standard Prometheus metrics via its `/metrics` endpoint — reconcile duration/count/errors (`controller_runtime_reconcile_*`), workqueue depth/latency (`workqueue_*`), and K8s client request stats (`rest_client_*`). These remain as-is; this OSEP does not duplicate them.

**Custom business metrics (new, via OpenTelemetry SDK):**

| Category | Metric name | Type | Description |
|----------|-------------|------|-------------|
| **BatchSandbox** | `controller.batchsandbox.pod.create.duration` | Histogram | Time to create a Pod for a BatchSandbox, by `result` |
| **BatchSandbox** | `controller.batchsandbox.pod.create.total` | Counter | Pod creation attempts by `result` |
| **BatchSandbox** | `controller.batchsandbox.task.schedule.duration` | Histogram | Task scheduling latency |
| **Pool** | `controller.pool.scale.total` | Counter | Pool scale operations by `direction` (`up`/`down`), `pool_name` |
| **Pool** | `controller.pool.size` | Gauge (Observable) | Current pool size by `pool_name`, `state` (`ready`/`pending`/`evicting`) |
| **Pool** | `controller.pool.allocation.duration` | Histogram | Time from allocation request seen to Pod assigned, by `pool_name` |
| **Snapshot** | `controller.snapshot.commit.duration` | Histogram | Image commit job duration by `result` |
| **Snapshot** | `controller.snapshot.commit.total` | Counter | Commit job attempts by `result` |

Meter name: **`opensandbox/controller`**.

**Coexistence with Prometheus:** Built-in controller-runtime Prometheus metrics and OTel business metrics coexist independently. Deployment topology is operator's choice:
- Prometheus scrapes `/metrics` directly for built-in metrics; OTel Collector receives OTLP for business metrics.
- Or OTel Collector scrapes `/metrics` (Prometheus receiver) and receives OTLP, unifying everything into one pipeline.
- Or business metrics use an OTel Prometheus exporter to merge onto the same `/metrics` endpoint.

This OSEP does not mandate a specific collection topology.

### 2. Distributed Tracing

#### 2.1 Correlation model

Server and controller emit **independent traces** — no trace context propagation between them. Correlation uses:

- **`sandbox_id`** attribute on all spans (both server and controller). In the trace backend, query `sandbox_id = "xxx"` to retrieve all traces related to that sandbox across both services.
- **Timestamps**: Server trace timestamp + controller reconcile trace timestamp allow chronological ordering.

This is the same pattern used by many Kubernetes operators where the control loop is asynchronous and decoupled from the API request.

**Example query in Grafana Tempo**:
```
{resource.service.name =~ "opensandbox-.*"} | sandbox_id = "sb-abc-123"
```

This returns both the server's `POST /sandboxes` trace and the controller's reconcile trace for that sandbox.

#### 2.2 Server spans

| Span name | When | Key attributes |
|-----------|------|----------------|
| `HTTP {method} {route}` | Every inbound HTTP request (middleware) | `http.method`, `http.route`, `http.status_code`, `sandbox_id` (when applicable) |
| `server.create_sandbox` | `POST /sandboxes` service layer | `sandbox_id`, `runtime_type`, `pool_name` (if pool-based) |
| `server.delete_sandbox` | `DELETE /sandboxes/{id}` | `sandbox_id` |
| `server.allocate_from_pool` | Pool allocation path | `pool_name`, `sandbox_id` |
| `server.create_snapshot` | `POST /sandboxes/{id}/snapshot` | `sandbox_id`, `snapshot_id` |
| `k8s.{verb}.{resource}` | Each K8s API call (wrapper around `K8sClient` / `kubernetes` Python client) | `k8s.verb`, `k8s.resource`, `k8s.namespace`, `k8s.status_code` |

The HTTP span is the root span for each request. Business operation spans are children. K8s API call spans are children of the operation span.

Note: The server calls the Kubernetes API via `K8sClient` (wrapping the `kubernetes` Python client library), not via `httpx`. Instrumentation should wrap `K8sClient` methods or the underlying `urllib3` transport used by the `kubernetes` client — `opentelemetry-instrumentation-httpx` does NOT cover these calls.

#### 2.3 Controller spans

| Span name | When | Key attributes |
|-----------|------|----------------|
| `controller.reconcile.{type}` | Each Reconcile() invocation | `controller`, `namespace`, `name`, `sandbox_id` (from CR) |
| `controller.create_pod` | Pod creation during reconcile | `pod_name`, `sandbox_id` |
| `controller.schedule_task` | Task scheduling | `sandbox_id`, `task_count` |
| `controller.scale_pool` | Pool scaling decision | `pool_name`, `direction`, `delta` |
| `controller.commit_snapshot` | Snapshot commit job creation | `sandbox_id`, `snapshot_id` |
| `k8s.{verb}.{resource}` | Each K8s API call | `k8s.verb`, `k8s.resource`, `k8s.namespace` |

The reconcile span is the root span in the controller's trace (independent trace_id from the server).

#### 2.4 Correlation with OSEP-0010 components

OSEP-0010 components (execd, egress, ingress) have metrics and logs with `sandbox_id`. Combined with server/controller traces also carrying `sandbox_id`, a single query retrieves the full observability picture for any sandbox:

- **Traces** (server + controller): latency breakdown of creation, reconciliation, pod scheduling.
- **Metrics** (all components): request rates, resource usage, policy enforcement counts.
- **Logs** (OSEP-0010): egress outbound access, policy changes.

### 3. Initialization and configuration

#### 3.1 Server (Python)

```python
# opensandbox_server/telemetry.py
def init_telemetry() -> Callable[[], None]:
    """
    Initialize OpenTelemetry TracerProvider and MeterProvider.
    Called once at app startup (lifespan).
    No-op if OTEL_EXPORTER_OTLP_ENDPOINT is unset.

    Returns a shutdown function that flushes and shuts down
    providers. Must be called during app lifespan shutdown
    to avoid losing buffered spans/metrics.
    """
```

- **TracerProvider**: OTLP span exporter (HTTP or gRPC), `BatchSpanProcessor`.
- **MeterProvider**: OTLP metric exporter, `PeriodicExportingMetricReader` (default 60s interval).
- **Propagator**: W3C TraceContext + Baggage (default composite).
- **Resource**: `service.name=opensandbox-server`, `service.version`, deployment attributes from env.
- **Integration**: Middleware on FastAPI for HTTP spans; manual instrumentation in service layer for business spans.

#### 3.2 Controller (Go)

```go
// internal/telemetry/init.go
func InitTelemetry(ctx context.Context, serviceName string) (shutdown func(context.Context) error, err error)
```

- **TracerProvider**: OTLP span exporter, `BatchSpanProcessor`.
- **MeterProvider**: OTLP metric exporter, `PeriodicReader`.
- **Resource**: `service.name=opensandbox-controller`, `service.version` (from build vars), deployment attributes.
- **Integration**: Wrap each `Reconcile()` method with span creation; extract `sandbox_id` from the CR and set as span attribute.

#### Environment variables (shared conventions)

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (unset = no export); generic fallback for all signals |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Per-signal override: OTLP endpoint for traces (takes precedence over generic) |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Per-signal override: OTLP endpoint for metrics (takes precedence over generic) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` or `http/protobuf` (default `http/protobuf`) |
| `OTEL_SERVICE_NAME` | Override service name |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes |
| `OTEL_TRACES_EXPORTER` | `otlp` or `none` |
| `OTEL_METRICS_EXPORTER` | `otlp` or `none` |
| `OTEL_TRACES_SAMPLER` | Sampler type (default `parentbased_traceidratio`) |
| `OTEL_TRACES_SAMPLER_ARG` | Sampler argument (default `1.0` = sample all) |

Per-signal endpoints allow operators to route traces and metrics to different collectors (e.g. traces → Tempo, metrics → Mimir). This is consistent with OSEP-0010 and the existing `components/internal/telemetry` implementation.

## Test Plan

- **Unit tests (Server)**
  - Mock OTLP exporter; fire HTTP requests; assert spans and metrics exported with correct attributes.
  - Verify `sandbox_id` present on business operation spans.
  - Verify no export and no errors when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset.

- **Unit tests (Controller)**
  - Mock OTLP exporter; trigger reconcile; assert spans created with correct attributes.
  - Verify `sandbox_id` extracted from CR and set on reconcile span.

- **Integration tests**
  - Start server and controller with OTLP endpoint pointing at a test collector.
  - Create a sandbox via API; verify:
    - Server span `server.create_sandbox` exported with `sandbox_id`.
    - Controller span `controller.reconcile.batchsandbox` exported with same `sandbox_id`.
    - Server metrics (`server.sandbox.create.duration`) present in OTLP export.
    - Controller business metrics (`controller.batchsandbox.pod.create.total`) present in OTLP export.
  - Query by `sandbox_id` in the backend returns traces from both services.

- **Sampling**
  - With `OTEL_TRACES_SAMPLER=traceidratio` and `OTEL_TRACES_SAMPLER_ARG=0`, no root spans exported. Verify no errors and no overhead beyond propagation bookkeeping. Note: if using the default `parentbased_traceidratio`, inbound requests carrying a sampled `traceparent` header will still be recorded; use a non-parent-based sampler to guarantee zero sampling.

## Drawbacks

- **Additional dependencies**: `opentelemetry-sdk`, `opentelemetry-exporter-otlp` for Python; `go.opentelemetry.io/otel` + exporters for Go. Increases binary/image size.
- **No single trace waterfall**: Server and controller traces are independent; debugging requires querying by `sandbox_id` to find both. This is a conscious tradeoff for simplicity — no CRD annotation coupling, no propagation code.
- **Sampling complexity**: In production, high QPS requires careful sampler tuning. Default sample-all is suitable for development but may overwhelm backends at scale.
- **Controller-runtime metric overlap**: Deployments using Prometheus scraping of controller-runtime metrics now have two metric sources for reconcile stats. Must document which to prefer or how to deduplicate.

## Alternatives

| Alternative | Why not chosen |
|-------------|----------------|
| Propagate `traceparent` via CRD annotations (SpanLink) | Adds annotation coupling, propagation code in both server and controller, and complexity for concurrent updates. `sandbox_id` correlation achieves equivalent debugging value with less invasiveness |
| Propagate `traceparent` via CRD `.spec` field | Pollutes user-facing API schema |
| Auto-instrument Python with `opentelemetry-instrument` CLI wrapper | Less control over span naming and attribute enrichment; prefer explicit instrumentation for business spans, auto-instrumentation only for HTTP layer |
| Skip tracing, rely on `request_id` + `sandbox_id` log correlation only | Sufficient for simple cases but does not provide latency breakdown, dependency graphs, or trace-native querying in backends like Tempo/Jaeger |

## Infrastructure Needed

- **Python dependencies**
  - `opentelemetry-api`
  - `opentelemetry-sdk`
  - `opentelemetry-exporter-otlp-proto-http` (or `-grpc`)
  - `opentelemetry-instrumentation-fastapi` (optional, for HTTP auto-spans)
  - `opentelemetry-instrumentation-urllib3` (for outbound K8s API calls via the `kubernetes` client's urllib3 transport)

- **Go dependencies**
  - `go.opentelemetry.io/otel`
  - `go.opentelemetry.io/otel/sdk`
  - `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (or gRPC)
  - `go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp`

- **Runtime**
  - OTLP-compatible collector or backend (e.g. OpenTelemetry Collector, Grafana Tempo, Jaeger with OTLP receiver).
  - For no-export mode: no extra infrastructure.

## Upgrade & Migration Strategy

- **Backward compatibility**: No changes to existing APIs, CRD schemas, or controller-runtime metric endpoints. Pure additive instrumentation.
- **Rollout**
  1. Add telemetry initialization code with OTLP endpoint unset (noop).
  2. Instrument server HTTP middleware and business operations.
  3. Instrument controller reconcile loops.
  4. Deploy with collector in test environment; validate traces and metrics.
  5. Enable in production with appropriate sampler ratio.
- **Rollback**: Unset `OTEL_EXPORTER_OTLP_ENDPOINT` or set `OTEL_TRACES_EXPORTER=none` / `OTEL_METRICS_EXPORTER=none` — immediately stops export.
- **Relationship to OSEP-0010**: This OSEP is additive. OSEP-0010 components continue with metrics+logs only. Cross-signal correlation relies on the shared `sandbox_id` dimension.
