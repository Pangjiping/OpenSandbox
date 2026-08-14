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

import com.alibaba.opensandbox.sandbox.config.ConnectionConfig
import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolCapacityExceededException
import com.alibaba.opensandbox.sandbox.domain.pool.AcquirePolicy
import com.alibaba.opensandbox.sandbox.domain.pool.PoolCreationSpec
import com.alibaba.opensandbox.sandbox.infrastructure.pool.InMemoryPoolStateStore
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Verifies the DIRECT_CREATE concurrency gate: direct creates share the
 * warmupConcurrency quota, concurrent fallback creates are bounded, and a
 * quota-exhausted acquire waits (bounded) then fails with
 * [PoolCapacityExceededException] instead of creating unboundedly.
 */
class SandboxPoolDirectCreateGateTest {
    private lateinit var lifecycle: MockWebServer
    private lateinit var execd: MockWebServer
    private val sandboxSeq = AtomicLong()

    @BeforeEach
    fun setUp() {
        lifecycle = MockWebServer()
        execd = MockWebServer()
        lifecycle.start()
        execd.start()
        execd.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse =
                    MockResponse().setResponseCode(200).setBody("""{"status":"ok"}""")
            }
    }

    @AfterEach
    fun tearDown() {
        lifecycle.shutdown()
        execd.shutdown()
    }

    private fun installLifecycleDispatcher(createAction: () -> Unit) {
        lifecycle.dispatcher =
            object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse {
                    val path = request.path.orEmpty()
                    return when {
                        request.method == "POST" && path == "/v1/sandboxes" -> {
                            createAction()
                            MockResponse().setResponseCode(201).setBody(
                                """{"id":"sbx-${sandboxSeq.incrementAndGet()}","status":{"state":"Running"},""" +
                                    """"createdAt":"2026-01-01T00:00:00Z","entrypoint":["tail"]}""",
                            )
                        }
                        request.method == "GET" && path.contains("/endpoints/") ->
                            MockResponse().setResponseCode(200).setBody(
                                """{"endpoint":"${execd.hostName}:${execd.port}","headers":{"X-EXECD-ACCESS-TOKEN":"t"}}""",
                            )
                        request.method == "POST" && path.endsWith("/renew-expiration") ->
                            MockResponse().setResponseCode(200).setBody("""{"expiresAt":"2026-12-31T00:00:00Z"}""")
                        request.method == "DELETE" -> MockResponse().setResponseCode(204)
                        else -> MockResponse().setResponseCode(404)
                    }
                }
            }
    }

    private fun buildPool(
        maxIdle: Int,
        warmupConcurrency: Int,
        acquireReadyTimeout: Duration = Duration.ofSeconds(30),
    ): SandboxPool =
        SandboxPool.builder()
            .poolName("direct-gate-test")
            .ownerId("owner")
            .maxIdle(maxIdle)
            .warmupConcurrency(warmupConcurrency)
            .stateStore(InMemoryPoolStateStore())
            .connectionConfig(
                ConnectionConfig.builder()
                    .domain(lifecycle.hostName + ":" + lifecycle.port)
                    .protocol("http")
                    .requestTimeout(Duration.ofSeconds(10))
                    .disableMetrics()
                    .build(),
            )
            .creationSpec(
                PoolCreationSpec.builder()
                    .image("test:latest")
                    .entrypoint("tail", "-f", "/dev/null")
                    .build(),
            )
            .reconcileInterval(Duration.ofMillis(100))
            .idleTimeout(Duration.ofMinutes(30))
            .acquireReadyTimeout(acquireReadyTimeout)
            .acquireSkipHealthCheck(false)
            .build()

    @Test
    fun `concurrent direct creates are bounded by warmupConcurrency`() {
        val concurrent = AtomicInteger()
        val maxConcurrent = AtomicInteger()
        installLifecycleDispatcher {
            val now = concurrent.incrementAndGet()
            maxConcurrent.updateAndGet { maxOf(it, now) }
            try {
                Thread.sleep(300)
            } finally {
                concurrent.decrementAndGet()
            }
        }

        val pool = buildPool(maxIdle = 0, warmupConcurrency = 2)
        pool.start()
        try {
            val workers = 6
            val threads = Executors.newFixedThreadPool(workers)
            val done = CountDownLatch(workers)
            val sandboxes = java.util.concurrent.ConcurrentLinkedQueue<com.alibaba.opensandbox.sandbox.Sandbox>()
            repeat(workers) {
                threads.submit {
                    try {
                        sandboxes.add(pool.acquire(Duration.ofMinutes(10), AcquirePolicy.DIRECT_CREATE))
                    } finally {
                        done.countDown()
                    }
                }
            }
            assertTrue(done.await(30, TimeUnit.SECONDS), "acquires did not complete")
            threads.shutdown()
            sandboxes.forEach { it.kill() }
            // 6 concurrent callers, gate = 2: server must never see more than 2
            // in-flight creates at once.
            assertTrue(
                maxConcurrent.get() <= 2,
                "expected direct creates bounded by warmupConcurrency=2, saw ${maxConcurrent.get()} concurrent",
            )
        } finally {
            pool.shutdown(graceful = false)
        }
    }

    @Test
    fun `quota exhausted acquire waits then fails with PoolCapacityExceededException`() {
        // The single warmup holds the only in-flight create slot until the
        // test releases it, so any acquire fallback must wait and then fail.
        val warmupRelease = CountDownLatch(1)
        installLifecycleDispatcher { warmupRelease.await(60, TimeUnit.SECONDS) }
        val pool =
            buildPool(
                maxIdle = 2,
                warmupConcurrency = 1,
                acquireReadyTimeout = Duration.ofSeconds(2),
            )
        pool.start()
        try {
            // Let the warmup occupy the single slot.
            val deadline = System.currentTimeMillis() + 5000
            while (lifecycle.requestCount < 1 && System.currentTimeMillis() < deadline) {
                Thread.sleep(50)
            }
            assertTrue(lifecycle.requestCount >= 1, "warmup create never reached the server")

            val start = System.currentTimeMillis()
            val failure =
                assertThrows(PoolCapacityExceededException::class.java) {
                    pool.acquire(Duration.ofMinutes(10), AcquirePolicy.DIRECT_CREATE)
                }
            val elapsed = System.currentTimeMillis() - start
            assertTrue(elapsed >= 1500, "expected bounded wait before failing, elapsed=${elapsed}ms")
            assertTrue(failure.message!!.contains("warmupConcurrency=1"))
        } finally {
            warmupRelease.countDown()
            pool.shutdown(graceful = false)
        }
    }
}
