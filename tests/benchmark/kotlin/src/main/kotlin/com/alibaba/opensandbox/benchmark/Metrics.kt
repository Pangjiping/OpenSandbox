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

/**
 * Thread-safe latency collector. Contention is negligible at the benchmark's
 * acquire rates, so a lock-protected ArrayList is sufficient.
 */
class LatencyCollector {
    private val lock = Any()
    private val samples = ArrayList<Long>()
    private var failures = 0L

    fun record(elapsedMs: Long) {
        synchronized(lock) {
            samples.add(elapsedMs)
        }
    }

    fun recordFailure() {
        synchronized(lock) {
            failures++
        }
    }

    fun snapshot(): LatencyStats {
        val sorted: LongArray
        var failureCount: Long
        synchronized(lock) {
            sorted = LongArray(samples.size)
            for ((i, v) in samples.withIndex()) sorted[i] = v
            sorted.sort()
            failureCount = failures
        }
        return LatencyStats(
            n = sorted.size.toLong(),
            failures = failureCount,
            meanMs = if (sorted.isEmpty()) 0.0 else sorted.average(),
            p50 = percentile(sorted, 0.50),
            p90 = percentile(sorted, 0.90),
            p95 = percentile(sorted, 0.95),
            p99 = percentile(sorted, 0.99),
            p999 = percentile(sorted, 0.999),
            maxMs = sorted.lastOrNull() ?: 0L,
        )
    }

    private fun percentile(sorted: LongArray, p: Double): Long {
        if (sorted.isEmpty()) return 0L
        val idx = ((sorted.size - 1) * p).toInt()
        return sorted[idx]
    }
}

data class LatencyStats(
    val n: Long,
    val failures: Long,
    val meanMs: Double,
    val p50: Long,
    val p90: Long,
    val p95: Long,
    val p99: Long,
    val p999: Long,
    val maxMs: Long,
) {
    fun toMap(): Map<String, Any> =
        mapOf(
            "count" to n,
            "failures" to failures,
            "meanMs" to meanMs,
            "p50Ms" to p50,
            "p90Ms" to p90,
            "p95Ms" to p95,
            "p99Ms" to p99,
            "p999Ms" to p999,
            "maxMs" to maxMs,
        )
}
