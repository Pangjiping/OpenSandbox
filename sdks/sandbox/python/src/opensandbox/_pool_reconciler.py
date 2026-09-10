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
"""Sandbox pool reconciliation logic.

Aligned with the Kotlin ``PoolReconciler``: one tick only reaps expired idle,
shrinks excess, computes the admission plan, and submits warmups through the
caller-provided callback. The tick returns immediately; warmup tasks create,
validate, renew, and commit their sandbox independently of the tick.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from opensandbox.pool_types import (
    PoolConfig,
    PoolState,
    PoolStateStore,
    calculate_warmup_plan,
)
from opensandbox.pool_types import (
    reap_expired_idle_with_min_ttl as _reap_expired_idle_with_min_ttl,
)

logger = logging.getLogger(__name__)


@dataclass
class ReconcileState:
    """Mutable observation state for the reconcile loop.

    Thread-safe for concurrent updates from warmup workers and reads from
    ``snapshot()``, mirroring the Kotlin ``@Synchronized`` counterpart.
    """

    degraded_threshold: int
    failure_count: int = 0
    state: PoolState = PoolState.HEALTHY
    last_error: str | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_success(self) -> None:
        with self._lock:
            self.failure_count = 0
            if self.state == PoolState.DEGRADED:
                self.state = PoolState.HEALTHY
            self.last_error = None

    def record_failure(self, error_message: str | None) -> None:
        self.record_failures(1, error_message)

    def record_failures(self, count: int, error_message: str | None) -> None:
        if count <= 0:
            return
        with self._lock:
            self.failure_count += count
            self.last_error = error_message
            if self.failure_count >= self.degraded_threshold:
                self.state = PoolState.DEGRADED

    def is_backoff_active(self, now: datetime | None = None) -> bool:
        """Replenish backoff is intentionally disabled; fixed create admission provides
        pressure control. Aligned with the Kotlin SDK's ``ReconcileState``."""
        return False


def run_reconcile_tick(
    *,
    config: PoolConfig,
    state_store: PoolStateStore,
    on_discard_sandbox: Callable[[str], None],
    submit_warmups: Callable[[int], None],
    warming_count: int = 0,
) -> bool:
    """Run one reconcile tick: leader-gated reap / shrink / admission planning.

    Returns whether this node holds the primary lock. Only the lock holder
    performs idle maintenance writes. Warmup submission is non-blocking: the
    caller-provided ``submit_warmups`` admits at most ``warmup_create_qps``
    creates whose in-flight count already participates in the deficit; the tick
    does not wait for them. The lock is not released at tick end — distributed
    stores rely on TTL or renew failure.
    """
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl

    if not state_store.try_acquire_primary_lock(pool_name, owner_id, ttl):
        logger.debug(f"Reconcile skip (not primary): pool_name={pool_name}")
        return False
    _run_primary_replenish_once(
        config=config,
        state_store=state_store,
        on_discard_sandbox=on_discard_sandbox,
        submit_warmups=submit_warmups,
        warming_count=warming_count,
    )
    # Do not release primary lock here; leader holds until renew fails or TTL expires.
    return True


def _run_primary_replenish_once(
    *,
    config: PoolConfig,
    state_store: PoolStateStore,
    on_discard_sandbox: Callable[[str], None],
    submit_warmups: Callable[[int], None],
    warming_count: int = 0,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl
    now = datetime.now(timezone.utc)

    discarded_alive = _reap_expired_idle_with_min_ttl(
        state_store, pool_name, now, config.acquire_min_remaining_ttl
    )
    for sandbox_id in discarded_alive:
        # Reaped near-expiry but server-side TTL has not elapsed; kill so the live sandbox
        # does not linger past its pool membership and consume quota.
        on_discard_sandbox(sandbox_id)
    counters = state_store.snapshot_counters(pool_name)
    excess = max(0, counters.idle_count - config.max_idle)
    to_remove = min(excess, int(config.warmup_concurrency or 1))
    if to_remove > 0:
        _shrink_excess_idle(config, state_store, on_discard_sandbox, to_remove)
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
        state_store.renew_primary_lock(pool_name, owner_id, ttl)
        logger.debug(
            f"Reconcile tick: pool_name={pool_name} idle={counters.idle_count} "
            f"warming={warming_count} deficit={deficit} to_submit=0"
        )
        return

    logger.debug(
        f"Reconcile tick: pool_name={pool_name} idle={counters.idle_count} "
        f"warming={warming_count} deficit={deficit} create_qps={config.warmup_create_qps} "
        f"to_submit={to_submit}"
    )

    if not state_store.renew_primary_lock(pool_name, owner_id, ttl):
        return
    submit_warmups(to_submit)


def _shrink_excess_idle(
    config: PoolConfig,
    state_store: PoolStateStore,
    on_discard_sandbox: Callable[[str], None],
    to_remove: int,
) -> None:
    pool_name = config.pool_name
    owner_id = str(config.owner_id)
    ttl = config.primary_lock_ttl
    removed = 0
    for _ in range(to_remove):
        if not state_store.renew_primary_lock(pool_name, owner_id, ttl):
            logger.warning(
                f"Reconcile lost primary lock before shrinking idle: pool_name={pool_name} removed={removed}"
            )
            return
        sandbox_id = state_store.try_take_idle(pool_name)
        if sandbox_id is None:
            return
        try:
            on_discard_sandbox(sandbox_id)
        except Exception as exc:
            logger.warning(
                f"Reconcile shrink sandbox cleanup failed: pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
            )
        removed += 1

    state_store.renew_primary_lock(pool_name, owner_id, ttl)
    logger.debug(f"Reconcile shrunk {removed} idle sandbox(es): pool_name={pool_name}")
