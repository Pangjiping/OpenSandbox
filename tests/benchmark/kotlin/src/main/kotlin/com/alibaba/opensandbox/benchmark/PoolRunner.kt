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

import com.alibaba.opensandbox.sandbox.pool.SandboxPool
import com.alibaba.opensandbox.sandbox.config.ConnectionConfig
import com.alibaba.opensandbox.sandbox.domain.pool.AcquirePolicy
import com.alibaba.opensandbox.sandbox.domain.pool.PoolCreationSpec
import com.alibaba.opensandbox.sandbox.domain.pool.PoolStateStore
import com.alibaba.opensandbox.sandbox.infrastructure.pool.InMemoryPoolStateStore
import java.time.Duration

/**
 * Builds a [SandboxPool] wired to the mock server. Health checks stay enabled
 * so the execd path (connect + readiness ping) is exercised.
 */
object PoolRunner {
    fun build(
        cfg: BenchmarkConfig,
        poolName: String,
        maxIdle: Int = cfg.maxIdle,
        warmupConcurrency: Int = cfg.warmupConcurrency,
        reconcileIntervalMs: Long = cfg.reconcileIntervalMs,
        idleTimeoutS: Long = cfg.idleTimeoutS,
        maxAcquireRetries: Int = cfg.staleRetries,
        acquireReadyTimeoutMs: Long = cfg.acquireReadyTimeoutMs,
        stateStore: PoolStateStore = InMemoryPoolStateStore(),
    ): SandboxPool {
        val connectionConfig =
            ConnectionConfig.builder()
                .domain(cfg.mockDomain)
                .protocol("http")
                .requestTimeout(Duration.ofSeconds(30))
                .disableMetrics()
                .build()
        return SandboxPool.builder()
            .poolName(poolName)
            .ownerId("bench-owner-$poolName")
            .maxIdle(maxIdle)
            .stateStore(stateStore)
            .connectionConfig(connectionConfig)
            .creationSpec(
                PoolCreationSpec.builder()
                    .image("benchmark:mock")
                    .entrypoint("tail", "-f", "/dev/null")
                    .build(),
            )
            .warmupConcurrency(warmupConcurrency)
            .reconcileInterval(Duration.ofMillis(reconcileIntervalMs))
            .acquireReadyTimeout(Duration.ofMillis(acquireReadyTimeoutMs))
            .warmupReadyTimeout(Duration.ofMillis(cfg.warmupReadyTimeoutMs))
            .acquireHealthCheckPollingInterval(Duration.ofMillis(cfg.healthCheckPollingIntervalMs))
            .warmupHealthCheckPollingInterval(Duration.ofMillis(cfg.healthCheckPollingIntervalMs))
            .idleTimeout(Duration.ofSeconds(idleTimeoutS))
            .maxAcquireRetries(maxAcquireRetries)
            .also { builder ->
                if (cfg.acquireMinRemainingTtlS > 0) {
                    builder.acquireMinRemainingTtl(Duration.ofSeconds(cfg.acquireMinRemainingTtlS))
                }
                if (cfg.primaryLockTtlS > 0) {
                    builder.primaryLockTtl(Duration.ofSeconds(cfg.primaryLockTtlS))
                }
                if (cfg.degradedThreshold > 0) {
                    builder.degradedThreshold(cfg.degradedThreshold)
                }
            }
            .build()
    }

    val DEFAULT_POLICY = AcquirePolicy.DIRECT_CREATE
    val RETRY_POLICY = AcquirePolicy.RETRY_NEXT_IDLE_THEN_CREATE

    /** Polls snapshot until idleCount reaches [target]; returns elapsed ms or -1 on timeout. */
    fun waitForIdle(
        pool: SandboxPool,
        target: Int,
        timeoutMs: Long,
    ): Long {
        val start = System.nanoTime()
        val deadline = start + timeoutMs * 1_000_000
        while (true) {
            val idle = pool.snapshot().idleCount
            if (idle >= target) {
                return (System.nanoTime() - start) / 1_000_000
            }
            if (System.nanoTime() > deadline) {
                return -1L
            }
            Thread.sleep(100)
        }
    }

    /** Polls snapshot until idleCount drops to [target] or below (shrink); returns elapsed ms or -1 on timeout. */
    fun waitForIdleBelow(
        pool: SandboxPool,
        target: Int,
        timeoutMs: Long,
    ): Long {
        val start = System.nanoTime()
        val deadline = start + timeoutMs * 1_000_000
        while (true) {
            val idle = pool.snapshot().idleCount
            if (idle <= target) {
                return (System.nanoTime() - start) / 1_000_000
            }
            if (System.nanoTime() > deadline) {
                return -1L
            }
            Thread.sleep(100)
        }
    }
}
