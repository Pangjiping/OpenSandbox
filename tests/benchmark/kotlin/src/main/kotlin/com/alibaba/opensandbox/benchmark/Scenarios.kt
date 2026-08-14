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
import com.alibaba.opensandbox.sandbox.pool.SandboxPool
import com.alibaba.opensandbox.sandbox.domain.pool.PoolState
import kotlinx.serialization.json.JsonPrimitive
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
                        latency.recordFailure()
                    }
                }
            }
        }
        start.countDown()
        threads.shutdown()
        threads.awaitTermination(10, TimeUnit.MINUTES)

        val createdDelta = num(mock.stats(), "stats.created") - createdBefore
        val acquires = rounds * workers.toLong()
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "latency" to latency.snapshot().toMap(),
            "acquires" to acquires,
            "serverCreatedDelta" to createdDelta,
            "hitRatio" to (1.0 - createdDelta.toDouble() / acquires).coerceIn(0.0, 1.0),
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

        val idleSamples = CopyOnWriteArrayList<Int>()
        val sampler = Thread {
            while (running.get()) {
                idleSamples.add(pool.snapshot().idleCount)
                Thread.sleep(500)
            }
        }
        sampler.isDaemon = true
        sampler.start()

        val rng = Random(System.nanoTime())
        val threads = Executors.newFixedThreadPool(cfg.steadyWorkers)
        repeat(cfg.steadyWorkers) {
            threads.submit {
                while (System.nanoTime() < deadline) {
                    val t0 = System.nanoTime()
                    try {
                        val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.DEFAULT_POLICY)
                        latency.record((System.nanoTime() - t0) / 1_000_000)
                        acquires.incrementAndGet()
                        Thread.sleep(rng.nextLong(cfg.holdMinMs, cfg.holdMaxMs + 1))
                        killAndClose(sb)
                    } catch (t: Throwable) {
                        latency.recordFailure()
                        Thread.sleep(200)
                    }
                }
            }
        }
        threads.shutdown()
        threads.awaitTermination(15, TimeUnit.MINUTES)
        running.set(false)

        val createdDelta = num(mock.stats(), "stats.created") - createdBefore
        val killedDelta = num(mock.stats(), "stats.killed") - killedBefore
        pool.shutdown(graceful = false)

        val idleMin = idleSamples.minOrNull() ?: 0
        val idleMean = if (idleSamples.isEmpty()) 0.0 else idleSamples.average()
        val idleZeroRatio =
            if (idleSamples.isEmpty()) 0.0
            else idleSamples.count { it == 0 }.toDouble() / idleSamples.size

        return mapOf(
            "fillTimeMs" to fillMs,
            "durationMs" to durationMs,
            "workers" to cfg.steadyWorkers,
            "throughputAcquiresPerSec" to (acquires.get().toDouble() / cfg.steadyDurationS),
            "latency" to latency.snapshot().toMap(),
            "serverCreatedDelta" to createdDelta,
            "serverKilledDelta" to killedDelta,
            "idleSamples" to idleSamples.size,
            "idleMin" to idleMin,
            "idleMean" to idleMean,
            "idleEmptyRatio" to idleZeroRatio,
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
                latency.recordFailure()
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

        // Poison every currently-alive sandbox: their execd endpoints start
        // failing, so idle candidates cannot be connected.
        mock.setFaults(poisonExisting = true)

        val latency = LatencyCollector()
        repeat(cfg.staleAcquires) {
            val t0 = System.nanoTime()
            try {
                val sb = pool.acquire(cfg.acquireTimeout, PoolRunner.RETRY_POLICY)
                latency.record((System.nanoTime() - t0) / 1_000_000)
                killAndClose(sb)
            } catch (t: Throwable) {
                latency.recordFailure()
            }
        }
        val stats = mock.stats()

        // Pool must drain the stale idles and refill with fresh sandboxes.
        val refillMs = PoolRunner.waitForIdle(pool, cfg.maxIdle, cfg.coldStartTimeoutMs)
        pool.shutdown(graceful = false)

        return mapOf(
            "fillTimeMs" to fillMs,
            "acquires" to cfg.staleAcquires,
            "latency" to latency.snapshot().toMap(),
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

    // ---------- helpers ----------

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
        )
}
