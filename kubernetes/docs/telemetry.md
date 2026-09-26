# Controller Telemetry (OpenTelemetry)

The sandbox controller emits OpenTelemetry metrics for the pool allocation path
and controller capacity. This document is the signal specification (names,
types, attributes, units) and the configuration guide for OTLP export.

Design principles (from
[opensandbox-group/OpenSandbox#1767](https://github.com/opensandbox-group/OpenSandbox/issues/1767)):

- Restrained by design: only core signals; no speculative instrumentation.
- Reuse what controller-runtime already exposes (workqueue depth, reconcile
  counts/durations, REST client metrics are served on the controller-runtime
  metrics endpoint — do not duplicate them here).
- Use standard OTel SDK instruments. Histograms are used instead of
  client-side quantile summaries so measurements aggregate across controller
  replicas.

## Allocator-path metrics

All instruments are `Float64Histogram` on meter scope `opensandbox/controller`,
recorded with unit `s` (seconds), with explicit bucket boundaries
`[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]` (seconds).
Success/error separation is expressed through the `success` boolean attribute;
histogram `count` per attribute set provides the success/error counts.

| Name | Attributes | Covers | Emitted from |
|---|---|---|---|
| `controller.allocator.schedule.duration` | `namespace`, `pool_name`, `success` | The schedule decision itself (`Allocator.Schedule`, including recovery, request building, and the packing algorithm) | `pool_controller.go` `scheduleSandbox` |
| `controller.allocator.persist_alloc_state.duration` | `namespace`, `pool_name`, `success` | Persisting allocation state: the `alloc-status` annotation Patch against the API server | `allocator.go` `annoAllocationSyncer.SetAllocation` |
| `controller.allocator.sync_alloc_result.duration` | `namespace`, `pool_name`, `success` | Syncing the batch allocation result to all sandboxes of a pool (the full concurrent sync round) | `pool_controller.go` `doAllocate` |
| `controller.allocator.sync_single_alloc_result.duration` | `namespace`, `pool_name`, `success` | Per-sandbox allocation-result sync (in-memory store update + annotation Patch); recorded for both `allocated` and `released` syncs | `pool_controller.go` `syncSandboxConcurrently` |

Attribute semantics:

- `namespace`: Kubernetes namespace of the Pool (or BatchSandbox for the
  per-sandbox instruments).
- `pool_name`: Pool name (`pool.name` semantics; `BatchSandbox.spec.poolRef`
  for the per-sandbox instruments).
- `success`: `true` when the operation completed without error, `false` otherwise.

### Cardinality decisions

Prior art (closed PR #731) carried a `sandbox_name` label on the per-sandbox
histogram. That is a cardinality risk and was intentionally dropped: the
attribute set is bounded by (namespace, pool_name, success) only. Per-sandbox
identity remains available through Kubernetes objects and events; traces are
the intended vehicle for per-sandbox latency attribution in a later phase.

The `namespace`/`pool_name` attributes are already used by the capacity
metrics below, keeping attribute conventions consistent across the controller.

## Capacity metrics

Gauge-style signals collected periodically from the informer cache (see
`capacity_metrics.go`, same meter scope `opensandbox/controller`). They
register on the same global OTel meter provider as the allocator metrics,
driven by a leader-elected manager Runnable (`capacity_metrics_runner.go`)
that unregisters on shutdown:

| Name | Type | Unit | Attributes |
|---|---|---|---|
| `controller.pool.pods` | ObservableGauge | `{pod}` | `namespace`, `pool_name`, `state` (`total`/`allocated`/`available`/`updated`) |
| `controller.pool.cpu.requested` | ObservableGauge | `{cpu}` | `namespace`, `pool_name`, `state` |
| `controller.pool.memory.requested` | ObservableGauge | `By` | `namespace`, `pool_name`, `state` |
| `controller.batchsandbox.count` | ObservableGauge | `{batchsandbox}` | `namespace`, `phase`, `allocation_mode` (`pool`/`direct`) |
| `controller.batchsandbox.pods` | ObservableGauge | `{pod}` | `namespace`, `state` (`desired`/`current`/`allocated`/`ready`), `allocation_mode` |
| `controller.capacity.collect.duration` | ObservableGauge | `s` | — |

## Controller-runtime metrics (reused, not duplicated)

The controller-runtime metrics endpoint (disabled by default; enable with
`--metrics-bind-address`) already exposes workqueue depth/latency, per-driver
reconcile counts and durations (`controller_runtime_reconcile_*`), and REST
client metrics. These are the source for reconcile health and workqueue
signals; the controller does not emit competing custom versions.

## Enabling OTLP export

All controller metrics export through one process-wide global OTel meter
provider, configured via controller flags (or standard `OTEL_*` environment
variables):

| Flag | Environment fallback | Default | Description |
|---|---|---|---|
| `--otel-endpoint` | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`, then `OTEL_EXPORTER_OTLP_ENDPOINT` | (empty = disabled) | Absolute OTLP/HTTP URL, e.g. `http://otel-collector:4318`. A URL without a path targets the default `/v1/metrics` path. |
| `--otel-headers` | (exporter default: `OTEL_EXPORTER_OTLP_HEADERS`) | (empty) | Comma-separated `key=value` headers attached to export requests, e.g. `authorization=Bearer abc`. |
| `--otel-export-interval` | — | `60s` | Interval between OTLP metric exports. |

Example:

```bash
/controller \
  --otel-endpoint=http://otel-collector.observability:4318 \
  --otel-headers='authorization=Bearer token' \
  --otel-export-interval=30s
```

Behavior:

- There is a single process-wide meter provider: all controller metrics
  (allocator histograms and capacity gauges) export through it. With no
  endpoint configured, the provider stays a no-op and nothing is exported.
- The capacity gauges register only on the elected leader (leader-elected
  Runnable); allocator histograms are recorded and exported on every replica.
- Export failures are retried by the OTLP exporter; setup/configuration errors
  never block controller startup (telemetry degrades with an error log).
- On shutdown the provider flushes pending data with a 5-second budget.

## Prometheus rendering

When exporting through an OTLP → Prometheus converter (e.g. the OpenTelemetry
Collector's `prometheusremotewrite` exporter or a Prometheus OTLP receiver),
dots become underscores and the unit is appended, for example:

```
controller_allocator_schedule_duration_seconds{namespace="default",pool_name="pool-a",success="true"}
```

## Testing

- `internal/telemetry/telemetry_test.go` — provider/exporter wiring, flag/env
  parsing, and an end-to-end export against a local HTTP server.
- `internal/controller/metrics_test.go` — metric emission, attribute sets,
  unit, and the absence of the `sandbox_name` attribute.
