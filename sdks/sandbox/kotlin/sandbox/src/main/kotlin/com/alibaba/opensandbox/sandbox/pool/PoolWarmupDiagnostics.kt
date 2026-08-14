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

package com.alibaba.opensandbox.sandbox.pool

/**
 * Diagnostic counters for the warmup pipeline.
 *
 * Benchmark/diagnostic aid only — not part of the public API contract.
 * Overhead is a single `System.nanoTime()` read plus a locked list append per
 * warmup event, and it is a no-op when never read. State is global (all
 * pools in the JVM share it), so reset before a single-pool experiment and
 * snapshot after it settles.
 *
 * Measured phases of one warmup task:
 * - queue wait: submission -> task picked up by a warmup worker
 * - create:    `createOneSandbox` (create + readiness + renew)
 * - commit:    lock + store putIdle when the sandbox enters the idle buffer
 * Plus the reconcile-tick cadence (submission driver) and the in-flight
 * warmup count trajectory.
 */
object PoolWarmupDiagnostics {
    data class PhaseStats(
        val count: Long,
        val meanMs: Double,
        val p50Ms: Long,
        val p95Ms: Long,
        val maxMs: Long,
    )

    data class Snapshot(
        val queueWaitMs: PhaseStats,
        val createDurationMs: PhaseStats,
        val commitDurationMs: PhaseStats,
        val tickIntervalMs: PhaseStats,
        val tickDurationMs: PhaseStats,
        val submitBurst: PhaseStats,
        val submitCalls: Long,
        val inFlightPeak: Int,
        val inFlightMean: Double,
        val createFailures: Map<String, Long>,
    )

    private val lock = Any()
    private val queueWaitNanos = ArrayList<Long>()
    private val createNanos = ArrayList<Long>()
    private val commitNanos = ArrayList<Long>()
    private val tickIntervalNanos = ArrayList<Long>()
    private val tickDurationNanos = ArrayList<Long>()
    private val submitBursts = ArrayList<Int>()
    private val failureReasons = LinkedHashMap<String, Long>()
    private var submitCalls = 0L
    private var inFlightSum = 0L
    private var inFlightSamples = 0L
    private var inFlightPeak = 0
    private var lastTickNanos = 0L

    fun reset() {
        synchronized(lock) {
            queueWaitNanos.clear()
            createNanos.clear()
            commitNanos.clear()
            tickIntervalNanos.clear()
            tickDurationNanos.clear()
            submitBursts.clear()
            failureReasons.clear()
            submitCalls = 0L
            inFlightSum = 0L
            inFlightSamples = 0L
            inFlightPeak = 0
            lastTickNanos = 0L
        }
    }

    fun recordQueueWait(nanos: Long) = synchronized(lock) { queueWaitNanos.add(nanos) }

    fun recordCreate(nanos: Long) = synchronized(lock) { createNanos.add(nanos) }

    fun recordCommit(nanos: Long) = synchronized(lock) { commitNanos.add(nanos) }

    /** Records the wall-clock spacing between reconcile ticks plus each tick's execution time. */
    fun recordTick(nowNanos: Long, durationNanos: Long) {
        synchronized(lock) {
            tickDurationNanos.add(durationNanos)
            if (lastTickNanos != 0L) {
                tickIntervalNanos.add(nowNanos - lastTickNanos)
            }
            lastTickNanos = nowNanos
        }
    }

    fun recordSubmitBurst(size: Int) {
        synchronized(lock) {
            submitCalls++
            submitBursts.add(size)
        }
    }

    fun recordInFlight(current: Int) {
        synchronized(lock) {
            if (current > inFlightPeak) inFlightPeak = current
            inFlightSum += current
            inFlightSamples++
        }
    }

    /** Records a failed createOneSandbox attempt: exception class + first words of the message. */
    fun recordCreateFailure(failure: Throwable) {
        val message = failure.message?.trim()?.take(80) ?: ""
        val key = "${failure.javaClass.simpleName}: $message"
        synchronized(lock) {
            failureReasons[key] = (failureReasons[key] ?: 0L) + 1
        }
    }

    fun snapshot(): Snapshot {
        val queueWait: LongArray
        val create: LongArray
        val commit: LongArray
        val tickInterval: LongArray
        val tickDuration: LongArray
        val bursts: IntArray
        val calls: Long
        val peak: Int
        val meanInFlight: Double
        val failures: Map<String, Long>
        synchronized(lock) {
            queueWait = queueWaitNanos.toLongArray()
            create = createNanos.toLongArray()
            commit = commitNanos.toLongArray()
            tickInterval = tickIntervalNanos.toLongArray()
            tickDuration = tickDurationNanos.toLongArray()
            bursts = submitBursts.toIntArray()
            calls = submitCalls
            peak = inFlightPeak
            meanInFlight = if (inFlightSamples == 0L) 0.0 else inFlightSum.toDouble() / inFlightSamples
            failures = failureReasons.toMap()
        }
        return Snapshot(
            queueWaitMs = phase(queueWait),
            createDurationMs = phase(create),
            commitDurationMs = phase(commit),
            tickIntervalMs = phase(tickInterval),
            tickDurationMs = phase(tickDuration),
            submitBurst = burstPhase(bursts),
            submitCalls = calls,
            inFlightPeak = peak,
            inFlightMean = meanInFlight,
            createFailures = failures,
        )
    }

    private fun phase(nanos: LongArray): PhaseStats {
        if (nanos.isEmpty()) return PhaseStats(0, 0.0, 0L, 0L, 0L)
        val sorted = nanos.copyOf()
        sorted.sort()
        return PhaseStats(
            count = sorted.size.toLong(),
            meanMs = sorted.average() / 1_000_000.0,
            p50Ms = sorted[(sorted.size - 1) / 2] / 1_000_000,
            p95Ms = sorted[((sorted.size - 1) * 95) / 100] / 1_000_000,
            maxMs = sorted.last() / 1_000_000,
        )
    }

    private fun burstPhase(bursts: IntArray): PhaseStats {
        if (bursts.isEmpty()) return PhaseStats(0, 0.0, 0L, 0L, 0L)
        val sorted = bursts.copyOf()
        sorted.sort()
        return PhaseStats(
            count = sorted.size.toLong(),
            meanMs = sorted.average(),
            p50Ms = sorted[(sorted.size - 1) / 2].toLong(),
            p95Ms = sorted[((sorted.size - 1) * 95) / 100].toLong(),
            maxMs = sorted.last().toLong(),
        )
    }
}
