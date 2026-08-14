# OpenSandbox Pool Benchmark

Reproducible, cross-SDK benchmark harness for the sandbox SDK **client pool**
(`SandboxPool` in the Kotlin/JVM SDK; Go/Python/JS pools can reuse the same
mock server). It runs a standalone mock of the lifecycle + execd API with
configurable provisioning latency and fault injection, drives the pool through
scenario workloads, and writes a JSON + Markdown report.

```
tests/benchmark/
├── mockserver/     # standalone Go mock server (lifecycle + execd + control endpoints)
├── kotlin/         # benchmark driver (JVM, uses the published Kotlin SDK)
├── configs/        # mock server scenario configs (latency / fault profiles)
├── run.sh          # one-shot orchestration: publish SDK -> start mock -> run driver
└── results/        # reports and mock logs (gitignored)
```

## Prerequisites

- Go (any recent version; mock server uses stdlib only)
- JDK 17+ (driver + Kotlin SDK; `run.sh` picks a suitable JDK automatically
  on macOS)
- A Gradle wrapper is included under `kotlin/`. The SDK sources are referenced
  in place (composite build), so no separate install is needed.

## Quick start

```bash
# default config: create/delete 300-800ms, execd ping 1-5s, others 50-100ms
./run.sh

# smoke run with fast provisioning
./run.sh --mock-config configs/fast.json -- --scenarios cold-start,warm-latency

# full control over the driver
./run.sh -- --max-idle 50 --warmup-concurrency 10 --steady-duration-s 120
```

`run.sh` performs three steps:

1. Builds the mock server (`go build` + exec).
2. Starts the mock server.
3. Runs the driver: `./gradlew run` with forwarded `--key value` args.

The Kotlin SDK is **built from source**: the driver uses a Gradle composite
build (`includeBuild` in `kotlin/settings.gradle.kts`), so the benchmark always
runs the checked-out SDK code and picks up SDK changes without any
publish/install step. `com.alibaba.opensandbox:sandbox:1.0.18` in
`kotlin/build.gradle.kts` is a module coordinate that the composite build
substitutes with the local `:sandbox` project (the version is informational).

Reports land in `results/run-<timestamp>/report.{json,md}`; the mock log is at
`results/mockserver.log`. Exit code is non-zero when a scenario fails.

## Mock server

The mock implements the API surface the SDK pool actually drives, per
`specs/sandbox-lifecycle.yml` and `specs/execd-api.yaml`:

| Endpoint | Behavior |
|---|---|
| `POST /v1/sandboxes` | Simulated provisioning: sleeps `createLatencyMs`, returns `Pending`, flips to `Running` after `bootDelayMs` |
| `GET /v1/sandboxes/{id}` | Sandbox info; 404 after kill/expiry |
| `POST /v1/sandboxes/{id}/renew-expiration` | Applies server-side TTL |
| `DELETE /v1/sandboxes/{id}` | Marks terminated; execd stops responding |
| `GET /v1/sandboxes/{id}/endpoints/{port}` | Returns the execd URL + a per-sandbox access token |
| execd (`/ping`, anything) | 200 when the sandbox is booted and healthy; **404** while `Pending`/expired/poisoned |

**Why execd answers 404 while a sandbox is not ready**: the SDK's readiness
check polls execd `/ping` (`Sandbox.checkReady`), and its retry interceptor
retries 5xx and transport errors with backoff. A 404 is non-retryable, so the
client polls at its configured `healthCheckPollingInterval` instead of paying
policy backoff — keeping the benchmark's latency numbers clean. The
`execdFailureRate` fault injects 500s when you *want* the retry policy
engaged.

**Why boot state lives in execd**: readiness is decided by execd `/ping`, not
the lifecycle GET, so the mock attributes each execd request to a sandbox via
the endpoint token and only answers once that sandbox is `Running`.

Server-side state and counters are exposed for the driver to validate pool
behavior (no over-creation, stale cleanup, hit ratio):

- `GET /__stats` — counters + per-route QPS/latency + live config
- `POST /__config` — runtime fault injection: `createFailureRate`,
  `execdFailureRate`, `bootDelayMs`, `poisonExisting` (flips all alive
  sandboxes to a failing state, simulating stale idles); latency knobs are
  runtime-mutable too (`createLatencyMs`, `latencyOverrides` — the latter
  replaces the whole per-route map)
- `POST /__reset` — zero counters and QPS history

### Per-API QPS tracking

The mock records an exact per-second count for every request on each route
(`lifecycle.create|get|delete|renew|endpoint`, `execd.ping|other`) in a ring
buffer (`-stats-window-sec`, default 1800s). `/__stats` returns per route:

```json
"lifecycle.create": {
  "total": 244, "qps1s": 2.0, "qps5s": 3.2, "qps60s": 1.8,
  "avgMs": 100.2, "maxMs": 101,
  "seriesStartUnixSec": 1786678587, "series": [2, 4, 2, ...]
}
```

- `total` counts since the last `__reset`; `series` is the per-second request
  count covering `seriesStartUnixSec .. now` (older than the window is
  dropped; the driver resets before each scenario so each section is
  self-contained).
- The driver attaches a QPS snapshot to **every scenario section**
  (`results.<scenario>.mockQps` in `report.json`), and the end-of-run totals
  live under `results.mockServerStats`. This is the server-side ground truth
  for offline analysis: warmup bursts, reconcile-tick load, replenish spikes,
  and per-API request mixes (e.g. how many `renew-expiration` calls each
  acquire generates).

For runs longer than the window, poll `GET /__stats` from your analysis tool
and accumulate the series yourself.

### Mock config (JSON)

```json
{
  "createLatencyMs": { "distribution": "lognormal", "meanMs": 800, "stddevMs": 400, "minMs": 50 },
  "createFailureRate": 0.0,
  "bootDelayMs": 300,
  "execdFailureRate": 0.0,
  "defaultTtlSeconds": 3600,
  "latencyOverrides": {
    "lifecycle.renew": { "distribution": "fixed", "meanMs": 20 },
    "lifecycle.endpoint": { "distribution": "lognormal", "meanMs": 100, "stddevMs": 30, "minMs": 10 },
    "execd.ping": { "distribution": "fixed", "meanMs": 40 }
  }
}
```

**Response time model** — three independent knobs:

| Knob | What it controls |
|---|---|
| `createLatencyMs` | `POST /v1/sandboxes` response time (the server sleeps this long) |
| `bootDelayMs` | How long a created sandbox stays `Pending`; during this window execd pings fail **immediately** with 404 (no latency is paid) and the SDK readiness poll keeps retrying at its polling interval |
| `latencyOverrides` | Response time per route: `lifecycle.get`, `lifecycle.delete`, `lifecycle.renew`, `lifecycle.endpoint`, `execd.ping`, `execd.other`. Routes without an override respond immediately; an override for `lifecycle.create` replaces `createLatencyMs`. Execd route latency only applies once the sandbox is booted — not-ready probes fail fast |

Default profile (no `-config`): create/delete uniform **300-800ms**, execd
`/ping` fixed **100ms**, all other APIs uniform **50-100ms**.

The readiness sequence a client observes is therefore: create latency, then a
few fast `404` polls while the sandbox boots, then one successful ping —
typically one ping for the default profile (fixed 100ms ping vs. max 300ms
boot window).

So the full create-to-ready time a client observes is
`createLatencyMs + bootDelayMs` plus one successful ping (once booted, the
ready execd pays its route latency). All latency knobs take a `LatencySpec`:
`distribution` is `uniform` (random between `minMs` and `maxMs`), `fixed`
(always `meanMs`), or `lognormal` (`meanMs`/`stddevMs`, floored at `minMs`).
They are also runtime-mutable via `POST /__config`; sending `latencyOverrides`
replaces the whole per-route map, and the resulting response times are visible
in `/__stats` per-route `avgMs`/`maxMs` and the QPS series.

Presets: `default.json`, `fast.json` (smoke tests), `slow.json`.

## Driver

Run the driver standalone (mock already up):

```bash
cd kotlin
./gradlew --console=plain run --args="--mock-base-url http://127.0.0.1:18080 --scenarios all"
```

### Scenarios

| Scenario | What it measures |
|---|---|
| `cold-start` | Time from `pool.start()` until idle buffer is full; over-creation check (server `created` vs `maxIdle`) |
| `warm-latency` | acquire p50/p90/p95/p99/p999 + hit ratio from a warm pool (`N` workers × `M` rounds) |
| `steady-state` | Sustained acquires/sec under concurrent loaders with hold time; idle trajectory (min/mean/empty ratio) |
| `replenish-lag` | Time for a released idle slot to be refilled (completion-driven reconcile) |
| `failure-injection` | Pool behavior at `createFailureRate` 60%: success rate, backoff, DEGRADED transition, recovery after fault removal |
| `stale-idle` | Poisoned idle candidates: retry cost, stale cleanup, refill with fresh sandboxes |
| `idle-expiry` | Self-healing under short server-side TTL: reap + recreate keeps the buffer near `maxIdle` |

### Driver options

| Option | Default | Meaning |
|---|---|---|
| `--scenarios` | `all` | Comma-separated list: `cold-start`, `warm-latency`, `steady-state`, `replenish-lag`, `failure-injection`, `stale-idle`, `idle-expiry` |
| `--mock-base-url` | `http://127.0.0.1:18080` | Mock lifecycle base URL |
| `--report-dir` | `results/run-<ts>` | Report output directory (`run.sh` passes an absolute path) |
| `--max-idle` | `20` | Pool idle-buffer target |
| `--warmup-concurrency` | `4` | Concurrent warmup creation workers |
| `--reconcile-interval-ms` | `1000` | Pool reconcile tick interval |
| `--idle-timeout-s` | `1800` | Server-side TTL applied to pool-created sandboxes |
| `--acquire-min-remaining-ttl-s` | `0` | Idle entries with less remaining TTL than this are discarded on acquire; `0` = SDK auto default (`min(60s, idleTimeout/2)`) |
| `--primary-lock-ttl-s` | `0` | Distributed primary-lock TTL; `0` = SDK default (60s). No effect with the in-memory state store (single node always holds the lock) |
| `--degraded-threshold` | `0` | Consecutive create failures before the pool enters DEGRADED; `0` = SDK default (3) |
| `--acquire-ready-timeout-ms` | `15000` | `checkReady` timeout when acquiring (idle connect + direct create) |
| `--warmup-ready-timeout-ms` | `15000` | `checkReady` timeout for warmup creations |
| `--health-check-polling-interval-ms` | `200` | `checkReady` probe interval (execd ping cadence) |
| `--cold-start-timeout-ms` | `120000` | Max time to wait for the pool to fill |
| `--warm-workers` | `16` | Loader threads in `warm-latency` |
| `--warm-rounds-per-worker` | `150` | Acquire rounds per `warm-latency` worker |
| `--steady-workers` | `16` | Loader threads in `steady-state` |
| `--steady-duration-s` | `60` | `steady-state` run duration |
| `--hold-min-ms` | `1000` | Lower bound of the random hold time per acquired sandbox in `steady-state` |
| `--hold-max-ms` | `5000` | Upper bound of the random hold time per acquired sandbox in `steady-state` |
| `--replenish-rounds` | `20` | Kill-and-wait repetitions in `replenish-lag` |
| `--replenish-wait-timeout-ms` | `15000` | Max time to wait for one replenished slot |
| `--failure-create-rate` | `0.6` | Create failure rate injected in `failure-injection` |
| `--failure-acquires` | `60` | Acquire attempts in `failure-injection` |
| `--stale-acquires` | `100` | Acquire attempts in `stale-idle` |
| `--stale-retries` | `3` | Pool `maxAcquireRetries` in `stale-idle` (idle candidates tried per acquire) |
| `--stale-acquire-ready-timeout-ms` | `3000` | `acquireReadyTimeout` in `stale-idle`; short because the SDK polls a failing execd for the full timeout before discarding a candidate |
| `--idle-expiry-idle-timeout-s` | `20` | `idleTimeout` in `idle-expiry` (short TTL so server-side expiry is exercised) |
| `--idle-expiry-duration-s` | `40` | `idle-expiry` run duration |

Each scenario resets the mock's counters and QPS history first, so
`report.json`'s per-scenario QPS sections cover exactly that scenario.

### Reproducing a production pool profile

Any `PoolConfig`-level profile maps 1:1 onto driver knobs. Example — a
large-pool / high-frequency-acquire / high-frequency-replenish production
profile (`maxIdle=13815, warmupConcurrency=1000, idleTtl=4h,
acquireMinRemainingTtl=15min, reconcile=30s, acquireReady=60s,
warmupReady=180s, primaryLockTtl=360s, degradedThreshold=5`):

```bash
./run.sh -- --max-idle 13815 --warmup-concurrency 1000 \
  --reconcile-interval-ms 30000 --idle-timeout-s 14400 \
  --acquire-min-remaining-ttl-s 900 --primary-lock-ttl-s 360 \
  --degraded-threshold 5 --acquire-ready-timeout-ms 60000 \
  --warmup-ready-timeout-ms 180000 --cold-start-timeout-ms 300000 \
  --scenarios cold-start,steady-state --steady-workers 300 \
  --steady-duration-s 120 --hold-min-ms 200 --hold-max-ms 2000
```

Notes for this kind of run:

- `--cold-start-timeout-ms` must cover a full fill: with
  `warmupConcurrency=1000` and the default profile (~2-6s per sandbox) a
  13815-sandbox pool fills in roughly 30-90s.
- At this scale each scenario still starts a fresh pool, but the mock's
  sandbox registry accumulates across scenarios (previous pools are not
  killed on non-graceful shutdown) — budget mock memory accordingly or run
  one scenario per invocation.
- For higher acquire frequency, shrink the `execd.ping` latency via
  `latencyOverrides` in the mock config: each acquire pays one readiness ping
  (100ms by default), which caps the sustainable acquire rate.
- `primaryLockTtl` and `drainTimeout` do not change single-node benchmark
  behavior (in-memory state store always grants the lock; the driver never
  shuts down gracefully); they are reproduced for config fidelity only.

For `warm-latency`, keep `maxIdle` comfortably above `--warm-workers` if you
want to measure pure idle-hit latency: when workers outnumber the idle buffer,
acquires drain it and fall through to direct create (which the `hitRatio`
column will show).

## Reusing the mock from other SDKs

Point any SDK's `ConnectionConfig` at the mock:

```kotlin
ConnectionConfig.builder()
    .domain("127.0.0.1:18080")  // lifecycle API (no scheme; driver adds /v1)
    .protocol("http")
    .build()
```

The Go SDK's `pool_test.go` shows the same wiring for Go. Health checks and
endpoint lookups behave like a real server, so the mock doubles as a
deterministic test fixture for SDK e2e-style tests.

## Adding a scenario

Implement it in `kotlin/.../benchmark/Scenarios.kt`, returning a
`Map<String, Any>` (nested maps render as sections in Markdown), register it in
`ALL_SCENARIOS`, and add a `--<key>` default in `Cli.kt` when it needs knobs.
