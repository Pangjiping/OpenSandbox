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

import com.alibaba.opensandbox.sandbox.domain.exceptions.PoolStateStoreUnavailableException
import com.alibaba.opensandbox.sandbox.domain.pool.IdleEntry
import com.alibaba.opensandbox.sandbox.domain.pool.PoolDestroyState
import com.alibaba.opensandbox.sandbox.domain.pool.PoolStateStore
import com.alibaba.opensandbox.sandbox.domain.pool.StoreCounters
import com.alibaba.opensandbox.sandbox.domain.pool.TakeIdleResult
import com.alibaba.opensandbox.sandbox.infrastructure.pool.InMemoryPoolStateStore
import java.time.Duration
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * A [PoolStateStore] wrapper that can be toggled into "outage" mode, where
 * every operation throws [PoolStateStoreUnavailableException]. Used to test
 * the pool's store-outage behavior (OSEP-0005): DIRECT_CREATE fallthrough
 * keeps acquire available; FAIL_FAST fails closed.
 */
class FailingPoolStateStore(
    private val delegate: PoolStateStore = InMemoryPoolStateStore(),
) : PoolStateStore {
    @Volatile
    private var failing = false
    private val errorCount = AtomicLong()

    fun setFailing(f: Boolean) {
        failing = f
    }

    fun errorCount(): Long = errorCount.get()

    private fun <T> gate(block: () -> T): T {
        if (failing) {
            errorCount.incrementAndGet()
            throw PoolStateStoreUnavailableException("simulated store outage")
        }
        return block()
    }

    override fun tryTakeIdle(poolName: String): String? = gate { delegate.tryTakeIdle(poolName) }

    override fun tryTakeIdle(
        poolName: String,
        minRemainingTtl: Duration,
    ): TakeIdleResult = gate { delegate.tryTakeIdle(poolName, minRemainingTtl) }

    override fun putIdle(
        poolName: String,
        sandboxId: String,
    ) = gate { delegate.putIdle(poolName, sandboxId) }

    override fun removeIdle(
        poolName: String,
        sandboxId: String,
    ) = gate { delegate.removeIdle(poolName, sandboxId) }

    override fun tryAcquirePrimaryLock(
        poolName: String,
        ownerId: String,
        ttl: Duration,
    ): Boolean = gate { delegate.tryAcquirePrimaryLock(poolName, ownerId, ttl) }

    override fun renewPrimaryLock(
        poolName: String,
        ownerId: String,
        ttl: Duration,
    ): Boolean = gate { delegate.renewPrimaryLock(poolName, ownerId, ttl) }

    override fun releasePrimaryLock(
        poolName: String,
        ownerId: String,
    ) = gate { delegate.releasePrimaryLock(poolName, ownerId) }

    override fun reapExpiredIdle(
        poolName: String,
        now: Instant,
    ) = gate { delegate.reapExpiredIdle(poolName, now) }

    override fun reapExpiredIdle(
        poolName: String,
        now: Instant,
        minRemainingTtl: Duration,
    ): List<String> = gate { delegate.reapExpiredIdle(poolName, now, minRemainingTtl) }

    override fun snapshotCounters(poolName: String): StoreCounters = gate { delegate.snapshotCounters(poolName) }

    override fun snapshotIdleEntries(poolName: String): List<IdleEntry> = gate { delegate.snapshotIdleEntries(poolName) }

    override fun getMaxIdle(poolName: String): Int? = gate { delegate.getMaxIdle(poolName) }

    override fun setMaxIdle(
        poolName: String,
        maxIdle: Int,
    ) = gate { delegate.setMaxIdle(poolName, maxIdle) }

    override fun setIdleEntryTtl(
        poolName: String,
        idleTtl: Duration,
    ) = gate { delegate.setIdleEntryTtl(poolName, idleTtl) }

    override fun getDestroyState(poolName: String): PoolDestroyState = gate { delegate.getDestroyState(poolName) }

    override fun beginDestroy(
        poolName: String,
        ownerId: String,
    ) = gate { delegate.beginDestroy(poolName, ownerId) }

    override fun clearPoolState(poolName: String) = gate { delegate.clearPoolState(poolName) }

    override fun markDestroyed(
        poolName: String,
        ownerId: String,
        tombstoneTtl: Duration?,
    ) = gate { delegate.markDestroyed(poolName, ownerId, tombstoneTtl) }
}
