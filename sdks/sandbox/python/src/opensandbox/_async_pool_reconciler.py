#
# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Async sandbox pool reconciliation logic.

Aligned with the Kotlin ``PoolReconciler``: one tick only reaps expired idle,
shrinks excess, computes the admission plan, and submits warmups through the
caller-provided callback. The tick returns immediately; warmup tasks create,
validate, renew, and commit their sandbox independently of the tick.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from opensandbox.pool_types import (
    AsyncPoolConfig,
    AsyncPoolStateStore,
    calculate_warmup_plan,
)
from opensandbox.pool_types import (
    reap_expired_idle_with_min_ttl_async as _reap_expired_idle_with_min_ttl_async,
)

logger = logging.getLogger(__name__)


async def run_async_reconcile_tick(
    *,
    config: AsyncPoolConfig,
    state_store: AsyncPoolStateStore,
    on_discard_sandbox: Callable[[str], Awaitable[None]],
    submit_warmups: Callable[[int], None],
    warming_count: int = 0,
) -> bool:
    """Async counterpart of ``run_reconcile_tick``.

    Returns whether this node holds the primary lock. Warmup submission is
    non-blocking; the tick does not wait for the admitted tasks.
    """
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl

    if not await state_store.try_acquire_primary_lock(pool_name, owner_id, ttl):
        logger.debug(f"Async reconcile skip (not primary): pool_name={pool_name}")
        return False
    await _run_primary_replenish_once(
        config=config,
        state_store=state_store,
        on_discard_sandbox=on_discard_sandbox,
        submit_warmups=submit_warmups,
        warming_count=warming_count,
    )
    # Do not release primary lock here; leader holds until renew fails or TTL expires.
    return True


async def _run_primary_replenish_once(
    *,
    config: AsyncPoolConfig,
    state_store: AsyncPoolStateStore,
    on_discard_sandbox: Callable[[str], Awaitable[None]],
    submit_warmups: Callable[[int], None],
    warming_count: int = 0,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl
    now = datetime.now(timezone.utc)

    discarded_alive = await _reap_expired_idle_with_min_ttl_async(
        state_store, pool_name, now, config.acquire_min_remaining_ttl
    )
    for sandbox_id in discarded_alive:
        await _discard(on_discard_sandbox, sandbox_id)
    counters = await state_store.snapshot_counters(pool_name)
    excess = max(0, counters.idle_count - config.max_idle)
    to_remove = min(excess, int(config.warmup_concurrency or 1))
    if to_remove > 0:
        await _shrink_excess_idle(config, state_store, on_discard_sandbox, to_remove)
        return

    # Aligned with the Kotlin WarmupPlan: idle sandboxes and already-admitted warmups
    # both count toward the target, and warmup_create_qps caps admissions per tick.
    # Admission is bounded by the deficit, so queued submissions cannot overshoot.
    deficit, to_submit = calculate_warmup_plan(
        idle_count=counters.idle_count,
        warming_count=warming_count,
        max_idle=config.max_idle,
        warmup_create_qps=config.warmup_create_qps,
    )
    if to_submit == 0:
        await state_store.renew_primary_lock(pool_name, owner_id, ttl)
        logger.debug(
            f"Async reconcile tick: pool_name={pool_name} idle={counters.idle_count} "
            f"warming={warming_count} deficit={deficit} to_submit=0"
        )
        return

    logger.debug(
        f"Async reconcile tick: pool_name={pool_name} idle={counters.idle_count} "
        f"warming={warming_count} deficit={deficit} create_qps={config.warmup_create_qps} "
        f"to_submit={to_submit}"
    )

    if not await state_store.renew_primary_lock(pool_name, owner_id, ttl):
        return
    submit_warmups(to_submit)


async def _shrink_excess_idle(
    config: AsyncPoolConfig,
    state_store: AsyncPoolStateStore,
    on_discard_sandbox: Callable[[str], Awaitable[None]],
    to_remove: int,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl
    removed = 0
    for _ in range(to_remove):
        if not await state_store.renew_primary_lock(pool_name, owner_id, ttl):
            logger.warning(
                f"Async reconcile lost primary lock before shrinking idle: pool_name={pool_name} removed={removed}"
            )
            return
        sandbox_id = await state_store.try_take_idle(pool_name)
        if sandbox_id is None:
            return
        await _discard(on_discard_sandbox, sandbox_id)
        removed += 1

    await state_store.renew_primary_lock(pool_name, owner_id, ttl)
    logger.debug(
        f"Async reconcile shrunk {removed} idle sandbox(es): pool_name={pool_name}"
    )


async def _discard(
    on_discard_sandbox: Callable[[str], Awaitable[None]], sandbox_id: str
) -> None:
    try:
        await on_discard_sandbox(sandbox_id)
    except Exception as exc:
        logger.warning(
            f"Async reconcile sandbox cleanup failed: sandbox_id={sandbox_id} error={exc}"
        )
