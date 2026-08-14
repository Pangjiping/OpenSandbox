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

import com.alibaba.opensandbox.sandbox.domain.pool.PoolState
import com.alibaba.opensandbox.sandbox.pool.SandboxPool
import java.lang.management.GarbageCollectorMXBean
import java.lang.management.ManagementFactory
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Continuous client-side instrumentation: JVM threads, heap/GC, and pool
 * health (snapshot-based) sampled every [intervalMs] during a scenario.
 */
class PoolProbe(
    private val pool: SandboxPool,
    private val intervalMs: Long = 500,
) {
    private val running = AtomicBoolean(true)
    private val threadCounts = ArrayList<Int>()
    private val heapUsedMb = ArrayList<Double>()
    private val idleSamples = ArrayList<Int>()
    private val degradedSamples = AtomicInteger()
    private val backoffSamples = AtomicInteger()
    private val inFlightMax = AtomicInteger()
    private val lock = Any()
    private var thread: Thread? = null

    private val threadBean = ManagementFactory.getThreadMXBean()
    private val memoryBean = ManagementFactory.getMemoryMXBean()
    private val gcBeans: List<GarbageCollectorMXBean> = ManagementFactory.getGarbageCollectorMXBeans()
    private val gcStartCount = gcBeans.sumOf { it.collectionCount }
    private val gcStartTimeMs = gcBeans.sumOf { it.collectionTime }

    init {
        // Peak thread count is reported relative to this probe's window.
        threadBean.resetPeakThreadCount()
    }

    fun start() {
        val t =
            Thread {
                while (running.get()) {
                    sample()
                    try {
                        Thread.sleep(intervalMs)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                        break
                    }
                }
            }
        t.isDaemon = true
        t.name = "bench-probe"
        thread = t
        t.start()
    }

    fun stop() {
        running.set(false)
        thread?.join(5000)
    }

    private fun sample() {
        val heap = memoryBean.heapMemoryUsage
        val snap = pool.snapshot()
        synchronized(lock) {
            threadCounts.add(threadBean.threadCount)
            heapUsedMb.add(heap.used / (1024.0 * 1024.0))
            idleSamples.add(snap.idleCount)
        }
        if (snap.state == PoolState.DEGRADED) degradedSamples.incrementAndGet()
        if (snap.backoffActive) backoffSamples.incrementAndGet()
        inFlightMax.accumulateAndGet(snap.inFlightOperations) { a, b -> maxOf(a, b) }
    }

    fun report(): Map<String, Any> {
        val threads: LongArray
        val heap: DoubleArray
        val idle: IntArray
        synchronized(lock) {
            threads = LongArray(threadCounts.size) { threadCounts[it].toLong() }
            heap = DoubleArray(heapUsedMb.size) { heapUsedMb[it] }
            idle = IntArray(idleSamples.size) { idleSamples[it] }
        }
        val zeroIdleRatio =
            if (idle.isEmpty()) 0.0 else idle.count { it == 0 }.toDouble() / idle.size
        return mapOf(
            "threads" to stat(threads),
            "threadPeakSinceProbeStart" to threadBean.peakThreadCount,
            "heapUsedMb" to stat(heap),
            "gcCollections" to (gcBeans.sumOf { it.collectionCount } - gcStartCount),
            "gcTimeMs" to (gcBeans.sumOf { it.collectionTime } - gcStartTimeMs),
            "poolIdleCount" to stat(idle.map { it.toLong() }.toLongArray()),
            "poolIdleZeroRatio" to zeroIdleRatio,
            "poolDegradedSamples" to degradedSamples.get(),
            "poolBackoffSamples" to backoffSamples.get(),
            "poolInFlightMax" to inFlightMax.get(),
        )
    }

    private fun stat(samples: LongArray): Map<String, Any> {
        if (samples.isEmpty()) return mapOf("samples" to 0, "min" to 0L, "mean" to 0.0, "max" to 0L)
        return mapOf(
            "samples" to samples.size,
            "min" to samples.min(),
            "mean" to samples.average(),
            "max" to samples.max(),
        )
    }

    private fun stat(samples: DoubleArray): Map<String, Any> {
        if (samples.isEmpty()) return mapOf("samples" to 0, "min" to 0.0, "mean" to 0.0, "max" to 0.0)
        return mapOf(
            "samples" to samples.size,
            "min" to samples.min(),
            "mean" to samples.average(),
            "max" to samples.max(),
        )
    }
}
