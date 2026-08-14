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

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.time.Duration
import java.time.Instant

fun main(args: Array<String>) {
    val cfg =
        try {
            Cli.parse(args)
        } catch (e: Exception) {
            System.err.println("error: ${e.message}")
            System.err.println(Cli.usage())
            kotlin.system.exitProcess(2)
        }

    val mock = MockControl(cfg.mockBaseUrl, Duration.ofSeconds(10))
    if (!mock.ping()) {
        System.err.println(
            "error: mock server not reachable at ${cfg.mockBaseUrl} " +
                "(start it first, e.g. via tests/benchmark/run.sh)",
        )
        kotlin.system.exitProcess(1)
    }

    val scenarios = mutableListOf<String>()
    for (name in cfg.scenarios) {
        if (name == "all") {
            scenarios.addAll(Scenarios.ALL_SCENARIOS.keys)
        } else {
            if (name !in Scenarios.ALL_SCENARIOS) {
                System.err.println("error: unknown scenario '$name' (available: ${Scenarios.ALL_SCENARIOS.keys})")
                kotlin.system.exitProcess(2)
            }
            scenarios.add(name)
        }
    }

    println("== OpenSandbox pool benchmark ==")
    println("mock: ${cfg.mockBaseUrl}  scenarios: $scenarios")
    println(
        "config: maxIdle=${cfg.maxIdle} warmupConcurrency=${cfg.warmupConcurrency} " +
            "reconcileIntervalMs=${cfg.reconcileIntervalMs} idleTimeoutS=${cfg.idleTimeoutS}",
    )

    val results = LinkedHashMap<String, Any?>()
    val perScenarioQps = LinkedHashMap<String, Any?>()
    for (name in scenarios) {
        println("\n-- scenario: $name --")
        val t0 = System.nanoTime()
        val section =
            try {
                Scenarios.ALL_SCENARIOS.getValue(name)(cfg, mock)
            } catch (t: Throwable) {
                System.err.println("scenario $name failed: $t")
                mapOf("error" to (t.message ?: t.toString()))
            }
        val elapsedMs = (System.nanoTime() - t0) / 1_000_000
        println("   completed in ${elapsedMs}ms")
        section.forEach { (k, v) -> println("   $k=$v") }
        results[name] = section
        // Precise per-API QPS observed by the mock during this scenario. The
        // mock ring keeps per-second counts; the series is included in the JSON
        // report for offline analysis.
        perScenarioQps[name] = mock.stats()["qps"]
    }
    results["perScenarioQps"] = perScenarioQps

    results["mockServerStats"] = mock.stats()

    val report =
        buildJsonObject {
            put("runId", "${Instant.now().toEpochMilli()}")
            put("timestamp", Instant.now().toString())
            put("config", toJsonElement(cfgValues(cfg)))
            put("results", toJsonElement(results))
        }

    val outDir = File(cfg.reportDir)
    outDir.mkdirs()
    File(outDir, "report.json").writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), report))
    File(outDir, "report.md").writeText(renderMarkdown(cfg, results))
    println("\n== done: report written to ${outDir.absolutePath}/report.{json,md} ==")
}

private fun cfgValues(cfg: BenchmarkConfig): Map<String, Any> =
    linkedMapOf(
        "mockBaseUrl" to cfg.mockBaseUrl,
        "scenarios" to cfg.scenarios,
        "maxIdle" to cfg.maxIdle,
        "warmupConcurrency" to cfg.warmupConcurrency,
        "reconcileIntervalMs" to cfg.reconcileIntervalMs,
        "idleTimeoutS" to cfg.idleTimeoutS,
        "acquireMinRemainingTtlS" to cfg.acquireMinRemainingTtlS,
        "primaryLockTtlS" to cfg.primaryLockTtlS,
        "degradedThreshold" to cfg.degradedThreshold,
        "acquireReadyTimeoutMs" to cfg.acquireReadyTimeoutMs,
        "warmupReadyTimeoutMs" to cfg.warmupReadyTimeoutMs,
        "healthCheckPollingIntervalMs" to cfg.healthCheckPollingIntervalMs,
        "warmWorkers" to cfg.warmWorkers,
        "warmRoundsPerWorker" to cfg.warmRoundsPerWorker,
        "steadyWorkers" to cfg.steadyWorkers,
        "steadyDurationS" to cfg.steadyDurationS,
        "acquireRatePerMin" to cfg.acquireRatePerMin,
        "holdMinMs" to cfg.holdMinMs,
        "holdMaxMs" to cfg.holdMaxMs,
        "failureCreateRate" to cfg.failureCreateRate,
        "staleRetries" to cfg.staleRetries,
    )

private fun toJsonElement(value: Any?): JsonElement =
    when (value) {
        is JsonElement -> value
        is Map<*, *> -> JsonObject(value.entries.associate { (k, v) -> k.toString() to toJsonElement(v) })
        is Iterable<*> -> JsonArray(value.map { toJsonElement(it) })
        is Double -> JsonPrimitive(value)
        is Float -> JsonPrimitive(value)
        is Long -> JsonPrimitive(value)
        is Int -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is String -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value.toDouble())
        null -> JsonPrimitive("")
        else -> JsonPrimitive(value.toString())
    }

private fun renderMarkdown(cfg: BenchmarkConfig, results: Map<String, Any?>): String {
    val sb = StringBuilder()
    sb.appendLine("# OpenSandbox Pool Benchmark")
    sb.appendLine()
    sb.appendLine("- runId: ${Instant.now().toEpochMilli()}")
    sb.appendLine("- mock: ${cfg.mockBaseUrl}")
    sb.appendLine(
        "- maxIdle: ${cfg.maxIdle}, warmupConcurrency: ${cfg.warmupConcurrency}, " +
            "reconcileIntervalMs: ${cfg.reconcileIntervalMs}, idleTimeoutS: ${cfg.idleTimeoutS}",
    )
    sb.appendLine()
    for ((scenario, section) in results) {
        if (scenario == "mockServerStats") continue
        sb.appendLine("## $scenario")
        sb.appendLine()
        if (section is Map<*, *>) {
            renderMap(sb, section as Map<String, Any>, "  ")
        }
        sb.appendLine()
    }
    sb.appendLine("## mock server stats (end of run)")
    sb.appendLine()
    if (results["mockServerStats"] is Map<*, *>) {
        renderMap(sb, results["mockServerStats"] as Map<String, Any>, "  ")
    }
    return sb.toString()
}

private fun renderMap(
    sb: StringBuilder,
    map: Map<*, *>,
    indent: String,
) {
    for ((k, v) in map) {
        if (k == "series") continue // full per-second series lives in report.json only
        when (v) {
            is Map<*, *> -> {
                sb.appendLine("$indent$k:")
                renderMap(sb, v, "$indent  ")
            }
            is List<*> -> sb.appendLine("$indent$k: ${v.joinToString(",")}")
            else -> sb.appendLine("$indent$k: $v")
        }
    }
}
