/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.opensandbox.benchmark

import com.alibaba.opensandbox.sandbox.Sandbox
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolAcquireFailedException
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolDestroyedException
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolEmptyException
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolNotRunningException
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolStateStoreUnavailableException
import com.alibaba.opensandbox.sandbox.domain.exceptions.SandboxReadyTimeoutException
import com.alibaba.opensandbox.sandbox.domain.pool.AcquirePolicy
import com.alibaba.opensandbox.sandbox.domain.pool.PoolState
import com.alibaba.opensandbox.sandbox.pool.SandboxPool
import kotlinx.serialization.json.JsonPrimitive
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.random.Random

/**
 * Benchmark scenarios. Every scenario returns a flat-ish map that the report
 * writer renders into JSON and Markdown. Each scenario owns a fresh pool and
 * shuts it down before returning.
 */
object Scenarios {

    // ---------- cold-start ----------

    fun coldStart(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "cold-start")
        pool.start()
        val t0 = System.nanoTime()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val stats = mock.stats()
        pool.shutdown(graceful = false)

        val created = num(stats, "stats.created")
        return mapOf(
            "fillTimeMs" to fillMs,
            "timedOut" to (fillMs < 0),
            "serverCreated" to created,
            "serverAliveAtFill" to num(stats, "alive"),
            "overCreationOvershoot" to (created - cfg.maxIdle).coerceAtLeast(0),
        )
    }

    // ---------- warm-pool acquire latency ----------

    fun warmLatency(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "warm-latency")
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")

        val latency = LatencyCollector()
        val start = CountDownLatch(1)
        val workers = cfg.warmWorkers
        val rounds = cfg.warmRoundsPerWorker
        val probe = PoolProbe(pool)
        probe.start()
        val threads = Executors.newFixedThreadPool(workers)
        repeat(workers) {
            threads.submit {
                start.await()
                repeat(rounds) {
                    val t0 = System.nanoTime()
                    try {
                        val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
                        latency.record((System.nanoTime() - t0) / 1_000_000)
                        killAndClose(sb)
                    } catch (t: Throwable) {
                        latency.recordFailure(classifyFailure(t))
                    }
                }
            }
        }
        start.countDown()
        threads.shutdown()
        threads.awaitTermination(10, TimeUnit.MINUTES)
        probe.stop()
        probe.writeCsv(File(cfg.reportDir, "client-warm-latency.csv"))

        val createdDelta = num(mock.stats(), "stats.created") - createdBefore
        val acquires = rounds * workers.toLong()
        val latencyStats = latency.snapshot()
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "latency" to latencyStats.toMap(),
            "acquires" to acquires,
            "successRate" to successRate(latencyStats),
            "serverCreatedDelta" to createdDelta,
            "hitRatio" to (1.0 - createdDelta.toDouble() / acquires).coerceIn(0.0, 1.0),
            "client" to probe.report(),
        )
    }

    // ---------- steady-state throughput ----------

    fun steadyState(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "steady-state")
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")
        val killedBefore = num(mock.stats(), "stats.killed")

        val durationMs = cfg.steadyDurationS * 1000L
        val deadline = System.nanoTime() + durationMs * 1_000_000
        val running = AtomicBoolean(true)
        val latency = LatencyCollector()
        val acquires = AtomicLong(0)

        val probe = PoolProbe(pool)
        probe.start()

        val rng = Random(System.nanoTime())
        val pacer = RatePacer(cfg.acquireRatePerMin)
        val threads = Executors.newFixedThreadPool(cfg.steadyWorkers)
        val loaderStart = System.nanoTime()
        repeat(cfg.steadyWorkers) {
            threads.submit {
                while (System.nanoTime() < deadline) {
                    pacer.waitForSlot()
                    val t0 = System.nanoTime()
                    try {
                        val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
                        latency.record((System.nanoTime() - t0) / 1_000_000)
                        acquires.incrementAndGet()
                        Thread.sleep(rng.nextLong(cfg.holdMinMs, cfg.holdMaxMs + 1))
                        killAndClose(sb)
                    } catch (t: Throwable) {
                        latency.recordFailure(classifyFailure(t))
                        Thread.sleep(200)
                    }
                }
            }
        }
        threads.shutdown()
        // The loaders run for the full configured duration; the wait must not
        // truncate them (a 15-min cap would silently halve a 30-min run).
        threads.awaitTermination(durationMs / 1000 + 300, TimeUnit.SECONDS)
        val loaderDurationMs = (System.nanoTime() - loaderStart) / 1_000_000
        running.set(false)
        probe.stop()
        probe.writeCsv(File(cfg.reportDir, "client-steady-state.csv"))

        val createdDelta = num(mock.stats(), "stats.created") - createdBefore
        val killedDelta = num(mock.stats(), "stats.killed") - killedBefore
        val latencyStats = latency.snapshot()
        val client = probe.report()
        pool.shutdown(graceful = false)

        val idleStat = client["poolIdleCount"] as Map<String, Any>
        return mapOf(
            "fillTimeMs" to fillMs,
            "durationMs" to durationMs,
            "actualLoaderDurationMs" to loaderDurationMs,
            "workers" to cfg.steadyWorkers,
            "targetAcquiresPerMin" to cfg.acquireRatePerMin,
            "acquiredCount" to acquires.get(),
            "achievedAcquiresPerMin" to
                (acquires.get().toDouble() * 60_000 / loaderDurationMs.coerceAtLeast(1)),
            "throughputAcquiresPerSec" to (acquires.get().toDouble() * 1000 / loaderDurationMs.coerceAtLeast(1)),
            "successRate" to successRate(latencyStats),
            "latency" to latencyStats.toMap(),
            "serverCreatedDelta" to createdDelta,
            "serverKilledDelta" to killedDelta,
            "replenishRatePerSec" to (createdDelta.toDouble() / cfg.steadyDurationS),
            "killRatePerSec" to (killedDelta.toDouble() / cfg.steadyDurationS),
            "directCreateRatio" to
                ((createdDelta - killedDelta).coerceAtLeast(0).toDouble() / acquires.get().coerceAtLeast(1)),
            "idleSamples" to (idleStat["samples"] as Int),
            "idleMin" to (idleStat["min"] as Long),
            "idleMean" to (idleStat["mean"] as Double),
            "idleEmptyRatio" to (client["poolIdleZeroRatio"] as Double),
            "client" to client,
        )
    }

    // ---------- replenish lag ----------

    fun replenishLag(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "replenish-lag")
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)

        val lags = LatencyCollector()
        var timedOut = 0L
        repeat(cfg.replenishRounds) {
            val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
            killAndClose(sb)
            val t0 = System.nanoTime()
            val lag = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.replenishWaitTimeoutMs)
            if (lag < 0) {
                timedOut++
            } else {
                lags.record(lag)
            }
            Thread.sleep(50)
        }
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "rounds" to cfg.replenishRounds,
            "replenishLagMs" to lags.snapshot().toMap(),
            "timedOutRounds" to timedOut,
        )
    }

    // ---------- creation-failure injection ----------

    fun failureInjection(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "failure-injection", maxAcquireRetries = 3)
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        pool.releaseAllIdle()

        mock.setFaults(createFailureRate = cfg.failureCreateRate)
        Thread.sleep(500)

        val latency = LatencyCollector()
        repeat(cfg.failureAcquires) {
            val t0 = System.nanoTime()
            try {
                val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.RETRY_POLICY)
                latency.record((System.nanoTime() - t0) / 1_000_000)
                killAndClose(sb)
            } catch (t: Throwable) {
                latency.recordFailure(classifyFailure(t))
            }
        }
        Thread.sleep(500)
        val snap = pool.snapshot()

        mock.setFaults(createFailureRate = 0.0)
        val refillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val stats = mock.stats()
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "createFailureRate" to cfg.failureCreateRate,
            "acquires" to cfg.failureAcquires,
            "latency" to latency.snapshot().toMap(),
            "poolStateAfterBurst" to snap.state.name,
            "backoffActive" to snap.backoffActive,
            "failureCount" to snap.failureCount,
            "lastError" to (snap.lastError ?: ""),
            "serverCreateFailed" to num(stats, "stats.createFailed"),
            "refillTimeMsAfterRecovery" to refillMs,
        )
    }

    // ---------- stale idle sandboxes ----------

    fun staleIdle(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool =
            PoolRunner.build(
                cfg,
                "stale-idle",
                maxAcquireRetries = cfg.staleRetries,
                acquireReadyTimeoutMs = cfg.staleAcquireReadyTimeoutMs,
            )
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")

        // Poison a fraction (default 1.0 = all) of the currently-alive
        // sandboxes: their execd endpoints start failing, so idle candidates
        // cannot be connected. Partial poisoning simulates real-world failure
        // where the pool must skip bad candidates and return good ones.
        mock.setFaults(poisonRate = cfg.stalePoisonRate)

        val latency = LatencyCollector()
        repeat(cfg.staleAcquires) {
            val t0 = System.nanoTime()
            try {
                val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.RETRY_POLICY)
                latency.record((System.nanoTime() - t0) / 1_000_000)
                killAndClose(sb)
            } catch (t: Throwable) {
                latency.recordFailure(classifyFailure(t))
            }
        }
        val stats = mock.stats()

        // Pool must drain the stale idles and refill with fresh sandboxes.
        val refillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "acquires" to cfg.staleAcquires,
            "poisonRate" to cfg.stalePoisonRate,
            "latency" to latency.snapshot().toMap(),
            "successRate" to successRate(latency.snapshot()),
            "serverExecdPoisoned" to num(stats, "stats.execdPoisoned"),
            "serverCreatedDelta" to (num(stats, "stats.created") - createdBefore),
            "serverAliveAfter" to num(stats, "alive"),
            "refillTimeMs" to refillMs,
        )
    }

    // ---------- server-side TTL self-heal ----------

    fun idleExpiry(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val idleTimeoutS = cfg.idleExpiryIdleTimeoutS
        val pool =
            PoolRunner.build(
                cfg,
                "idle-expiry",
                maxIdle = 10,
                warmupConcurrency = 2,
                reconcileIntervalMs = 500,
                idleTimeoutS = idleTimeoutS,
            )
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, 10, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")

        val durationMs = cfg.idleExpiryDurationS * 1000L
        val deadline = System.nanoTime() + durationMs * 1_000_000
        val running = AtomicBoolean(true)
        val idleSamples = CopyOnWriteArrayList<Int>()
        val sampler = Thread {
            while (running.get()) {
                idleSamples.add(pool.snapshot().idleCount)
                Thread.sleep(250)
            }
        }
        sampler.isDaemon = true
        sampler.start()

        while (System.nanoTime() < deadline) {
            Thread.sleep(100)
        }
        running.set(false)

        val stats = mock.stats()
        val createdDelta = num(stats, "stats.created") - createdBefore
        val idleMean = if (idleSamples.isEmpty()) 0.0 else idleSamples.average()
        val idleMin = idleSamples.minOrNull() ?: 0
        pool.shutdown(graceful = false)

        return mapOf(
            "idleTimeoutS" to idleTimeoutS,
            "fillTimeMs" to fillMs,
            "durationMs" to durationMs,
            "serverCreatedDelta" to createdDelta,
            "serverKilled" to num(stats, "stats.killed"),
            "idleMean" to idleMean,
            "idleMin" to idleMin,
            "idleSamples" to idleSamples.size,
        )
    }

    // ---------- resize (shrink + regrow) ----------

    fun resize(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "resize")
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")
        val killedBefore = num(mock.stats(), "stats.killed")

        // Shrink: excess idles must be drained and killed by reconcile.
        val shrinkTarget = maxOf(1, cfg.maxIdle / 2)
        pool.resize(shrinkTarget)
        val shrinkMs = PoolRunner.waitForIdleBelow(pool, shrinkTarget, cfg.coldStartTimeoutMs)
        Thread.sleep(1000) // let server-side kills settle
        val killedDuringShrink = num(mock.stats(), "stats.killed") - killedBefore

        // Regrow back to the original target.
        pool.resize(cfg.maxIdle)
        val regrowMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val stats = mock.stats()
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "shrinkTo" to shrinkTarget,
            "shrinkTimeMs" to shrinkMs,
            "killedDuringShrink" to killedDuringShrink,
            "regrowTimeMs" to regrowMs,
            "serverCreatedDelta" to (num(stats, "stats.created") - createdBefore),
            "serverAliveAtEnd" to num(stats, "alive"),
        )
    }

    // ---------- acquire racing graceful shutdown ----------

    fun shutdownRace(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val pool = PoolRunner.build(cfg, "shutdown-race")
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)

        val shutdownStarted = AtomicBoolean(false)
        val stop = AtomicBoolean(false)
        // Collector 1: attempts while the pool is RUNNING. Collector 2: the
        // race window itself (acquires racing DRAINING/STOPPED).
        val runningLatency = LatencyCollector()
        val raceLatency = LatencyCollector()
        val runningAttempts = AtomicLong(0)
        val raceAttempts = AtomicLong(0)
        val threads = Executors.newFixedThreadPool(cfg.steadyWorkers)
        repeat(cfg.steadyWorkers) {
            threads.submit {
                while (!stop.get()) {
                    val inRace = shutdownStarted.get()
                    if (inRace) raceAttempts.incrementAndGet() else runningAttempts.incrementAndGet()
                    val latency = if (inRace) raceLatency else runningLatency
                    try {
                        val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
                        latency.record(0)
                        killAndClose(sb)
                    } catch (t: Throwable) {
                        latency.recordFailure(classifyFailure(t))
                    }
                }
            }
        }
        Thread.sleep(2000) // let workers hammer the warm pool
        shutdownStarted.set(true)
        val shutdownT0 = System.nanoTime()
        pool.shutdown(graceful = true)
        val shutdownMs = (System.nanoTime() - shutdownT0) / 1_000_000
        stop.set(true)
        threads.shutdownNow()
        threads.awaitTermination(30, TimeUnit.SECONDS)

        val runningStats = runningLatency.snapshot()
        val raceStats = raceLatency.snapshot()
        return mapOf(
            "fillTimeMs" to fillMs,
            "runningPhaseAttempts" to runningAttempts.get(),
            "runningPhase" to
                mapOf(
                    "successRate" to successRate(runningStats),
                    "latency" to runningStats.toMap(),
                ),
            "raceWindowAttempts" to raceAttempts.get(),
            "raceWindow" to
                mapOf(
                    "successRate" to successRate(raceStats),
                    "latency" to raceStats.toMap(),
                    "rejectedDuringDraining" to (raceStats.failuresByType["poolNotRunning"] ?: 0L),
                ),
            "shutdownMs" to shutdownMs,
        )
    }

    // ---------- state-store outage (OSEP-0005 fallthrough) ----------

    fun storeOutage(cfg: BenchmarkConfig, mock: MockControl): Map<String, Any> {
        mock.reset()
        val store = FailingPoolStateStore()
        val pool =
            PoolRunner.build(
                cfg,
                "store-outage",
                maxAcquireRetries = 1,
                stateStore = store,
            )
        pool.start()
        val fillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val createdBefore = num(mock.stats(), "stats.created")

        // Drain part of the idle buffer before the outage so recovery has
        // real refill work (the pool cannot commit warmups while the store
        // is down, and fallthrough acquires never touch the store).
        val drainCount = maxOf(1, cfg.maxIdle / 3)
        repeat(drainCount) {
            val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
            killAndClose(sb)
        }

        // Phase 1: store down, DIRECT_CREATE policy must fall through to
        // direct create (OSEP-0005) and keep acquire available.
        store.setFailing(true)
        Thread.sleep(500)
        val phase1 = LatencyCollector()
        repeat(cfg.failureAcquires) {
            val t0 = System.nanoTime()
            try {
                val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
                phase1.record((System.nanoTime() - t0) / 1_000_000)
                killAndClose(sb)
            } catch (t: Throwable) {
                phase1.recordFailure(classifyFailure(t))
            }
        }
        val phase1Stats = phase1.snapshot()
        val errorsPhase1 = store.errorCount()

        // Phase 2: store still down, FAIL_FAST must fail closed and surface
        // PoolStateStoreUnavailableException.
        val phase2 = LatencyCollector()
        repeat(10) {
            try {
                val sb = pool.acquire(cfg.acquireTimeout, AcquirePolicy.FAIL_FAST)
                phase2.record(0)
                killAndClose(sb)
            } catch (t: Throwable) {
                phase2.recordFailure(classifyFailure(t))
            }
        }
        val phase2Stats = phase2.snapshot()

        // Phase 3: store recovers; the pool must refill.
        store.setFailing(false)
        val refillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        val stats = mock.stats()
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "phase1DirectCreateFallthrough" to phase1Stats.toMap(),
            "phase1StoreErrorCount" to errorsPhase1,
            "phase2FailFastFailClosed" to phase2Stats.toMap(),
            "refillTimeMsAfterRecovery" to refillMs,
            "serverCreatedDelta" to (num(stats, "stats.created") - createdBefore),
        )
    }

    // ---------- helpers ----------

    private fun successRate(stats: LatencyStats): Double {
        val total = stats.n + stats.failures
        return if (total == 0L) 0.0 else (stats.n.toDouble() / total)
    }

    private fun classifyFailure(t: Throwable): String =
        when (t) {
            is SandboxReadyTimeoutException -> "readyTimeout"
            is PoolNotRunningException -> "poolNotRunning"
            is PoolEmptyException -> "poolEmpty"
            is PoolAcquireFailedException -> "acquireFailed"
            is PoolDestroyedException -> "poolDestroyed"
            is PoolStateStoreUnavailableException -> "storeUnavailable"
            else -> "other"
        }

    private fun killAndClose(sandbox: Sandbox) {
        try {
            sandbox.kill()
        } finally {
            try {
                sandbox.close()
            } catch (_: Exception) {
                // ignore
            }
        }
    }

    private fun num(stats: Map<String, Any?>, dottedKey: String): Long {
        var cur: Any? = stats
        for (part in dottedKey.split(".")) {
            if (cur !is Map<*, *>) return 0L
            cur = cur[part]
        }
        return when (cur) {
            is Number -> cur.toLong()
            is String -> cur.toLongOrNull() ?: 0L
            is JsonPrimitive -> cur.content.toLongOrNull() ?: 0L
            else -> 0L
        }
    }

    val ALL_SCENARIOS =
        mapOf(
            "cold-start" to ::coldStart,
            "warm-latency" to ::warmLatency,
            "steady-state" to ::steadyState,
            "replenish-lag" to ::replenishLag,
            "failure-injection" to ::failureInjection,
            "stale-idle" to ::staleIdle,
            "idle-expiry" to ::idleExpiry,
            "resize" to ::resize,
            "shutdown-race" to ::shutdownRace,
            "store-outage" to ::storeOutage,
        )
}
