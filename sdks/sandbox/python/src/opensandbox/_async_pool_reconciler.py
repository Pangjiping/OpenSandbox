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
"""Async sandbox pool reconciliation logic."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from opensandbox._pool_reconciler import ReconcileState
from opensandbox.pool_types import (
    AsyncPoolConfig,
    AsyncPoolStateStore,
)
from opensandbox.pool_types import (
    reap_expired_idle_with_min_ttl_async as _reap_expired_idle_with_min_ttl_async,
)

logger = logging.getLogger(__name__)


async def run_async_reconcile_tick(
    *,
    config: AsyncPoolConfig,
    state_store: AsyncPoolStateStore,
    create_one: Callable[[], Awaitable[str | None]],
    on_discard_sandbox: Callable[[str], Awaitable[None]],
    reconcile_state: ReconcileState,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl

    if not await state_store.try_acquire_primary_lock(pool_name, owner_id, ttl):
        logger.debug(f"Async reconcile skip (not primary): pool_name={pool_name}")
        return
    await _run_primary_replenish_once(
        config=config,
        state_store=state_store,
        create_one=create_one,
        on_discard_sandbox=on_discard_sandbox,
        reconcile_state=reconcile_state,
    )


async def _run_primary_replenish_once(
    *,
    config: AsyncPoolConfig,
    state_store: AsyncPoolStateStore,
    create_one: Callable[[], Awaitable[str | None]],
    on_discard_sandbox: Callable[[str], Awaitable[None]],
    reconcile_state: ReconcileState,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl
    now = datetime.now(timezone.utc)

    discarded_alive = await _reap_expired_idle_with_min_ttl_async(
        state_store, pool_name, now, config.acquire_min_remaining_ttl
    )
    for sandbox_id in discarded_alive:
        await on_discard_sandbox(sandbox_id)
    counters = await state_store.snapshot_counters(pool_name)
    excess = max(0, counters.idle_count - config.max_idle)
    to_remove = min(excess, int(config.warmup_concurrency or 1))
    if to_remove > 0:
        await _shrink_excess_idle(config, state_store, on_discard_sandbox, to_remove)
        return

    deficit = max(0, config.max_idle - counters.idle_count)
    to_create = min(deficit, int(config.warmup_concurrency or 1))
    if to_create == 0 or reconcile_state.is_backoff_active(now):
        await state_store.renew_primary_lock(pool_name, owner_id, ttl)
        return

    if not await state_store.renew_primary_lock(pool_name, owner_id, ttl):
        return

    tasks: set[asyncio.Future[str | None]] = {
        asyncio.ensure_future(create_one()) for _ in range(to_create)
    }
    pending = set(tasks)
    handled_tasks: set[asyncio.Future[str | None]] = set()
    failure_count = 0
    last_error: str | None = None
    created = 0
    commit_failed = False
    commit_error: str | None = None
    accept_commits = True
    dropped = 0
    stop_reason: str | None = None
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                try:
                    sandbox_id = task.result()
                except asyncio.CancelledError:
                    failure_count += 1
                    last_error = "warmup task cancelled"
                    handled_tasks.add(task)
                    continue
                except Exception as exc:
                    failure_count += 1
                    last_error = str(exc)
                    handled_tasks.add(task)
                    continue
                if sandbox_id is None:
                    failure_count += 1
                    last_error = None
                    handled_tasks.add(task)
                    continue

                if not accept_commits:
                    await _discard(on_discard_sandbox, sandbox_id)
                    dropped += 1
                    handled_tasks.add(task)
                    continue
                try:
                    lock_renewed = await state_store.renew_primary_lock(
                        pool_name, owner_id, ttl
                    )
                except Exception as exc:
                    lock_renewed = False
                    commit_failed = True
                    commit_error = str(exc)
                    stop_reason = "primary lock renewal failed"
                if not lock_renewed:
                    accept_commits = False
                    stop_reason = stop_reason or "primary lock lost"
                    await _discard(on_discard_sandbox, sandbox_id)
                    dropped += 1
                    handled_tasks.add(task)
                    continue
                try:
                    await state_store.put_idle(pool_name, sandbox_id)
                    created += 1
                except Exception as exc:
                    accept_commits = False
                    stop_reason = "commit failed"
                    commit_failed = True
                    commit_error = str(exc)
                    try:
                        await state_store.remove_idle(pool_name, sandbox_id)
                    except Exception:
                        pass
                    await _discard(on_discard_sandbox, sandbox_id)
                    dropped += 1
                handled_tasks.add(task)
    finally:
        unhandled_tasks = tasks - handled_tasks
        if unhandled_tasks:
            cleanup_task = asyncio.create_task(
                _cleanup_unhandled_tasks(
                    tasks=unhandled_tasks,
                    state_store=state_store,
                    pool_name=pool_name,
                    on_discard_sandbox=on_discard_sandbox,
                )
            )
            cleanup_cancellation: asyncio.CancelledError | None = None
            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError as exc:
                    cleanup_cancellation = cleanup_cancellation or exc
                    continue
            cleanup_task.result()
            if cleanup_cancellation is not None:
                raise cleanup_cancellation

    reconcile_state.record_failures(failure_count, last_error)
    if created > 0:
        reconcile_state.record_success()
    if commit_failed:
        reconcile_state.record_failure(commit_error)

    if dropped > 0:
        error_detail = f" error={commit_error}" if commit_error else ""
        logger.warning(
            f"Async reconcile {stop_reason}; dropped {dropped} newly created sandbox(es): pool_name={pool_name}{error_detail}"
        )
    if created > 0:
        logger.debug(
            f"Async reconcile created {created} sandboxes: pool_name={pool_name}"
        )


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


async def _cleanup_unhandled_tasks(
    *,
    tasks: set[asyncio.Future[str | None]],
    state_store: AsyncPoolStateStore,
    pool_name: str,
    on_discard_sandbox: Callable[[str], Awaitable[None]],
) -> None:
    for task in tasks:
        if not task.done():
            task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    discarded = 0
    for sandbox_id in results:
        if isinstance(sandbox_id, BaseException) or sandbox_id is None:
            continue
        try:
            await state_store.remove_idle(pool_name, sandbox_id)
        except Exception:
            pass
        await _discard(on_discard_sandbox, sandbox_id)
        discarded += 1
    if discarded > 0:
        logger.warning(
            f"Async reconcile interrupted; discarded {discarded} uncommitted sandbox(es): pool_name={pool_name}"
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
