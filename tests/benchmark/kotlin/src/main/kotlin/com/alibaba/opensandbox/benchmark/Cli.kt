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

import java.time.Duration

/**
 * All benchmark knobs, parsed from `--key value` command-line arguments.
 */
data class BenchmarkConfig(
    val mockBaseUrl: String,
    val reportDir: String,
    val scenarios: List<String>,
    val maxIdle: Int,
    val warmupConcurrency: Int,
    val reconcileIntervalMs: Long,
    val idleTimeoutS: Long,
    val acquireReadyTimeoutMs: Long,
    val warmupReadyTimeoutMs: Long,
    val healthCheckPollingIntervalMs: Long,
    val coldStartTimeoutMs: Long,
    val warmWorkers: Int,
    val warmRoundsPerWorker: Int,
    val steadyWorkers: Int,
    val steadyDurationS: Int,
    val holdMinMs: Long,
    val holdMaxMs: Long,
    val replenishRounds: Int,
    val replenishWaitTimeoutMs: Long,
    val failureCreateRate: Double,
    val failureAcquires: Int,
    val staleAcquires: Int,
    val staleRetries: Int,
    val staleAcquireReadyTimeoutMs: Long,
    val idleExpiryIdleTimeoutS: Long,
    val idleExpiryDurationS: Int,
) {
    val mockDomain: String
        get() = mockBaseUrl.removePrefix("http://").removePrefix("https://").trimEnd('/')
}

object Cli {
    private val allKeys =
        listOf(
            "mock-base-url",
            "report-dir",
            "scenarios",
            "max-idle",
            "warmup-concurrency",
            "reconcile-interval-ms",
            "idle-timeout-s",
            "acquire-ready-timeout-ms",
            "warmup-ready-timeout-ms",
            "health-check-polling-interval-ms",
            "cold-start-timeout-ms",
            "warm-workers",
            "warm-rounds-per-worker",
            "steady-workers",
            "steady-duration-s",
            "hold-min-ms",
            "hold-max-ms",
            "replenish-rounds",
            "replenish-wait-timeout-ms",
            "failure-create-rate",
            "failure-acquires",
            "stale-acquires",
            "stale-retries",
            "stale-acquire-ready-timeout-ms",
            "idle-expiry-idle-timeout-s",
            "idle-expiry-duration-s",
        )

    fun parse(args: Array<String>): BenchmarkConfig {
        val map = mutableMapOf<String, String>()
        var i = 0
        while (i < args.size) {
            val key = args[i]
            if (!key.startsWith("--")) {
                throw IllegalArgumentException("unexpected argument: $key")
            }
            val name = key.removePrefix("--")
            val value = args.getOrNull(i + 1) ?: throw IllegalArgumentException("missing value for $key")
            if (name !in allKeys) {
                throw IllegalArgumentException("unknown option: $key")
            }
            map[name] = value
            i += 2
        }
        return BenchmarkConfig(
            mockBaseUrl = map["mock-base-url"] ?: "http://127.0.0.1:18080",
            reportDir = map["report-dir"] ?: "results/run-${System.currentTimeMillis()}",
            scenarios =
                (map["scenarios"] ?: "all").split(",").map { it.trim() }.filter { it.isNotEmpty() },
            maxIdle = (map["max-idle"] ?: "20").toInt(),
            warmupConcurrency = (map["warmup-concurrency"] ?: "4").toInt(),
            reconcileIntervalMs = (map["reconcile-interval-ms"] ?: "1000").toLong(),
            idleTimeoutS = (map["idle-timeout-s"] ?: "1800").toLong(),
            acquireReadyTimeoutMs = (map["acquire-ready-timeout-ms"] ?: "15000").toLong(),
            warmupReadyTimeoutMs = (map["warmup-ready-timeout-ms"] ?: "15000").toLong(),
            healthCheckPollingIntervalMs = (map["health-check-polling-interval-ms"] ?: "200").toLong(),
            coldStartTimeoutMs = (map["cold-start-timeout-ms"] ?: "120000").toLong(),
            warmWorkers = (map["warm-workers"] ?: "16").toInt(),
            warmRoundsPerWorker = (map["warm-rounds-per-worker"] ?: "150").toInt(),
            steadyWorkers = (map["steady-workers"] ?: "16").toInt(),
            steadyDurationS = (map["steady-duration-s"] ?: "60").toInt(),
            holdMinMs = (map["hold-min-ms"] ?: "1000").toLong(),
            holdMaxMs = (map["hold-max-ms"] ?: "5000").toLong(),
            replenishRounds = (map["replenish-rounds"] ?: "20").toInt(),
            replenishWaitTimeoutMs = (map["replenish-wait-timeout-ms"] ?: "15000").toLong(),
            failureCreateRate = (map["failure-create-rate"] ?: "0.6").toDouble(),
            failureAcquires = (map["failure-acquires"] ?: "60").toInt(),
            staleAcquires = (map["stale-acquires"] ?: "100").toInt(),
            staleRetries = (map["stale-retries"] ?: "3").toInt(),
            staleAcquireReadyTimeoutMs = (map["stale-acquire-ready-timeout-ms"] ?: "3000").toLong(),
            idleExpiryIdleTimeoutS = (map["idle-expiry-idle-timeout-s"] ?: "20").toLong(),
            idleExpiryDurationS = (map["idle-expiry-duration-s"] ?: "40").toInt(),
        )
    }

    fun usage(): String =
        buildString {
            appendLine("Usage: pool-benchmark [--key value ...]")
            allKeys.forEach { appendLine("  --$it <value>") }
        }
}

val BenchmarkConfig.acquireTimeout: Duration get() = Duration.ofMinutes(10)
