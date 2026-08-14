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

import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * Spreads acquires evenly over wall-clock time at a fixed per-minute rate.
 *
 * Every caller claims the next absolute slot (`start + k * interval`); slots
 * are advanced with CAS so concurrent workers never share one. Slots that
 * fall in the past are executed immediately, so a slow worker lets the rate
 * catch up on the next slots — the long-run average stays at [ratePerMin]
 * without drift. No-op when [ratePerMin] is <= 0.
 */
class RatePacer(private val ratePerMin: Int) {
    private val intervalNanos =
        if (ratePerMin <= 0) 0L else TimeUnit.MINUTES.toNanos(1) / ratePerMin
    private val nextSlot = AtomicLong(0)

    /** Blocks until this caller's slot is due. */
    fun waitForSlot() {
        if (intervalNanos <= 0) return
        var slot = nextSlot.get()
        while (true) {
            if (slot == 0L) {
                if (nextSlot.compareAndSet(0L, System.nanoTime())) {
                    slot = System.nanoTime()
                    break
                }
                slot = nextSlot.get()
                continue
            }
            val next = slot + intervalNanos
            if (nextSlot.compareAndSet(slot, next)) {
                break
            }
            slot = nextSlot.get()
        }
        val waitMs = (slot - System.nanoTime()) / 1_000_000
        if (waitMs > 0) {
            try {
                Thread.sleep(waitMs)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }
}
