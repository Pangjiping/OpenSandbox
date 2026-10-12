# Copyright 2026 The OpenSandbox Authors
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

"""Idle sweeper: the OSEP-0024 auto-pause loop.

Multi-replica without leader election: the per-sandbox lock admits one
replica per idle episode, and FastPath PauseSandbox is an idempotent CAS, so
a lost race still converges to a single pause.

Gates (first failure drops the candidate for this sweep): opt-in -> Running
-> expiry -> idle (value / tombstone / unknown) -> probe (declared probes
are pause-exempt until the probe pipeline lands) -> lock -> re-verify ->
PauseSandbox. Any Redis failure skips the sweep; the worst case is a missed
pause, never a lost sandbox.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence

from redis.asyncio import Redis
from redis.exceptions import RedisError

from opensandbox_server.config import AppConfig
from opensandbox_server.integrations.idle_pause.activity import ActivityRegistry
from opensandbox_server.integrations.idle_pause.decision import IdleVerdict, evaluate_idle
from opensandbox_server.integrations.idle_pause.executor import (
    FastPathPauseExecutor,
    PauseExecutor,
    PauseOutcome,
)
from opensandbox_server.integrations.idle_pause.inventory import (
    FastSandboxInventory,
    SandboxCandidate,
    SandboxInventory,
)
from opensandbox_server.integrations.idle_pause.locking import PauseLockManager
from opensandbox_server.integrations.idle_pause.logutil import (
    IDLEP_EVENT_PAUSE_ISSUED,
    IDLEP_EVENT_SWEEP_COMPLETED,
    IDLEP_EVENT_SWEEP_SKIPPED,
    IDLEP_EVENT_TOMBSTONED,
    IDLEP_SOURCE_SWEEPER,
    idlep_bundle,
)
from opensandbox_server.integrations.idle_pause.metrics import record_pause_request
from opensandbox_server.integrations.idle_pause.redis_client import (
    close_idle_pause_redis_client,
    connect_idle_pause_redis_from_config,
)
from opensandbox_server.services.composite_service import CompositeSandboxService
from opensandbox_server.services.fast_sandbox.service import FastSandboxService

logger = logging.getLogger(__name__)


def _default_clock() -> int:
    return time.time_ns() // 1_000_000


@dataclass
class SweepStats:
    candidates: int = 0
    opted_in: int = 0
    paused: int = 0
    gated: int = 0
    tombstoned: int = 0
    failed: int = 0
    details: list[str] = field(default_factory=list)


class IdlePauseSweeper:
    """Periodically pauses opted-in fast sandboxes that stayed idle for >= X."""

    def __init__(
        self,
        *,
        namespace_resolver: Callable[[], Sequence[str]],
        inventory: SandboxInventory,
        activity: ActivityRegistry,
        locks: PauseLockManager,
        executor: PauseExecutor,
        sweep_interval_seconds: float = 15.0,
        lock_owner: Optional[str] = None,
        clock: Callable[[], int] = _default_clock,
        owned_redis: Optional[Redis] = None,
    ) -> None:
        # Re-resolved every sweep: tenants hot-reload and HTTP providers may
        # enumerate late.
        self._namespace_resolver = namespace_resolver
        self._inventory = inventory
        self._activity = activity
        self._locks = locks
        self._executor = executor
        self._interval = float(sweep_interval_seconds)
        self._lock_owner = lock_owner or f"sweeper-{id(self):x}"
        self._clock = clock
        # Set only when this sweeper created the client; caller-supplied
        # clients stay the caller's to close.
        self._owned_redis = owned_redis
        self._task: Optional[asyncio.Task[None]] = None
        self._stopping = asyncio.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "IdlePauseSweeper":
        if self._task is None or self._task.done():
            self._stopping.clear()
            self._task = asyncio.create_task(self._run_loop(), name="idle_pause_sweeper")
        return self

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        if self._owned_redis is not None:
            client, self._owned_redis = self._owned_redis, None
            try:
                await close_idle_pause_redis_client(client)
            except Exception as exc:  # noqa: BLE001 - shutdown must proceed
                logger.debug(f"idle_pause redis close deferred error={exc!s}")

    async def _run_loop(self) -> None:
        while not self._stopping.is_set():
            started = time.monotonic()
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception(f"idle_pause sweep error={exc!s}")
            elapsed = time.monotonic() - started
            delay = max(0.0, self._interval - elapsed)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass

    # -- sweep -------------------------------------------------------------

    async def sweep_once(self) -> SweepStats:
        """One full pass over all namespaces; never raises."""
        stats = SweepStats()
        try:
            await self._activity.ping()
        except (RedisError, OSError) as exc:
            line, ex = idlep_bundle(
                event=IDLEP_EVENT_SWEEP_SKIPPED,
                source=IDLEP_SOURCE_SWEEPER,
                skip_reason="redis_unreachable",
                error_type=type(exc).__name__,
            )
            logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
            return stats

        namespaces = list(dict.fromkeys(self._namespace_resolver()))
        for namespace in namespaces:
            candidates = await asyncio.to_thread(self._inventory.snapshot, namespace)
            await self._sweep_namespace(namespace, candidates, stats)

        line, ex = idlep_bundle(
            event=IDLEP_EVENT_SWEEP_COMPLETED,
            source=IDLEP_SOURCE_SWEEPER,
            candidates=stats.candidates,
            opted_in=stats.opted_in,
            paused=stats.paused,
            gated=stats.gated,
            tombstoned=stats.tombstoned,
            failed=stats.failed,
        )
        logger.info(f"idle_pause {line}", extra=ex)
        return stats

    async def _sweep_namespace(
        self, namespace: str, candidates: list[SandboxCandidate], stats: SweepStats
    ) -> None:
        stats.candidates += len(candidates)
        now_ms = self._clock()

        # Pure candidate gates first; survivors reach the shared Redis read.
        eligible = [
            c
            for c in candidates
            if self._passes_static_gates(c, now_ms, stats)
        ]
        if not eligible:
            return

        try:
            activity = await self._activity.read_many([c.sandbox_id for c in eligible])
        except (RedisError, OSError) as exc:
            line, ex = idlep_bundle(
                event=IDLEP_EVENT_SWEEP_SKIPPED,
                source=IDLEP_SOURCE_SWEEPER,
                namespace=namespace,
                skip_reason="redis_read_failed",
                error_type=type(exc).__name__,
            )
            logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
            return

        for candidate in eligible:
            await self._evaluate_candidate(candidate, activity.get(candidate.sandbox_id), stats)

    def _passes_static_gates(
        self, candidate: SandboxCandidate, now_ms: int, stats: SweepStats
    ) -> bool:
        policy = candidate.policy
        if policy is None or not policy.auto_pause_enabled:
            return False  # opt-in gate
        stats.opted_in += 1
        if candidate.state != "Running":
            return False  # Pausing/Paused need no action; Resuming is protected
        if candidate.expires_at is not None:
            expires_ms = int(candidate.expires_at.timestamp() * 1000)
            if expires_ms <= now_ms:
                return False  # the expiry path owns expired sandboxes
        return True

    async def _evaluate_candidate(
        self,
        candidate: SandboxCandidate,
        last_active_ms: Optional[int],
        stats: SweepStats,
    ) -> None:
        assert candidate.policy is not None and candidate.policy.idle_timeout_seconds is not None
        threshold = candidate.policy.idle_timeout_seconds
        now_ms = self._clock()

        # Idle gate: pure function of the activity key and its tombstone.
        if not await self._decide(candidate, last_active_ms, now_ms, threshold, stats):
            return

        # A declared probe must veto busy sandboxes; until the probe pipeline
        # lands, declaring one keeps the sandbox pause-exempt.
        if candidate.policy.active_probe is not None:
            record_pause_request(outcome="gated")
            stats.gated += 1
            stats.details.append(f"{candidate.sandbox_id}:active_probe_declared")
            return

        try:
            acquired = await self._locks.try_acquire(candidate.sandbox_id, self._lock_owner)
        except (RedisError, OSError) as exc:
            # Redis died mid-sweep: drop this candidate, never raise past the
            # sweep — remaining candidates and namespaces keep their shot.
            line, ex = idlep_bundle(
                event=IDLEP_EVENT_SWEEP_SKIPPED,
                source=IDLEP_SOURCE_SWEEPER,
                sandbox_id=candidate.sandbox_id,
                namespace=candidate.namespace,
                skip_reason="lock_acquire_failed",
                error_type=type(exc).__name__,
            )
            logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
            record_pause_request(outcome="gated")
            stats.gated += 1
            return
        if not acquired:
            record_pause_request(outcome="gated")
            stats.gated += 1
            stats.details.append(f"{candidate.sandbox_id}:lock_contended")
            return
        try:
            # Re-verify under lock: a request may have landed since the batch
            # read; a newer observation drops us.
            try:
                current = await self._activity.read(candidate.sandbox_id)
            except (RedisError, OSError) as exc:
                line, ex = idlep_bundle(
                    event=IDLEP_EVENT_SWEEP_SKIPPED,
                    source=IDLEP_SOURCE_SWEEPER,
                    sandbox_id=candidate.sandbox_id,
                    namespace=candidate.namespace,
                    skip_reason="reverify_read_failed",
                    error_type=type(exc).__name__,
                )
                logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
                record_pause_request(outcome="gated")
                stats.gated += 1
                return
            if current != last_active_ms:
                record_pause_request(outcome="gated")
                stats.gated += 1
                stats.details.append(f"{candidate.sandbox_id}:activity_changed")
                return

            await self._issue_pause(candidate, threshold, now_ms, last_active_ms, stats)
        finally:
            # Best-effort; TTL is the primary release path.
            try:
                await self._locks.release(candidate.sandbox_id, self._lock_owner)
            except (RedisError, OSError) as exc:
                logger.debug(f"idle_pause lock release deferred to TTL error={exc!s}")

    async def _decide(
        self,
        candidate: SandboxCandidate,
        last_active_ms: Optional[int],
        now_ms: int,
        threshold: int,
        stats: SweepStats,
    ) -> bool:
        tombstone_ms: Optional[int] = None
        if last_active_ms is None:
            try:
                tombstone_ms = await self._activity.read_tombstone(candidate.sandbox_id)
            except (RedisError, OSError) as exc:
                # Never pause from unknown state — but say so, or a Redis
                # fault confined here would silently stop tombstone pauses.
                line, ex = idlep_bundle(
                    event=IDLEP_EVENT_SWEEP_SKIPPED,
                    source=IDLEP_SOURCE_SWEEPER,
                    sandbox_id=candidate.sandbox_id,
                    namespace=candidate.namespace,
                    skip_reason="tombstone_read_failed",
                    error_type=type(exc).__name__,
                )
                logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
                return False
        decision = evaluate_idle(
            last_active_ms=last_active_ms,
            tombstone_ms=tombstone_ms,
            now_ms=now_ms,
            threshold_seconds=threshold,
        )
        if decision.create_tombstone:
            # First observation of unknown state: start the tombstone clock
            # and skip — a missing key must never accelerate a pause.
            try:
                await self._activity.ensure_tombstone(
                    candidate.sandbox_id,
                    now_ms=now_ms,
                    extra_ttl_seconds=max(0, int(self._interval)),
                )
            except (RedisError, OSError) as exc:
                line, ex = idlep_bundle(
                    event=IDLEP_EVENT_SWEEP_SKIPPED,
                    source=IDLEP_SOURCE_SWEEPER,
                    sandbox_id=candidate.sandbox_id,
                    namespace=candidate.namespace,
                    skip_reason="tombstone_write_failed",
                    error_type=type(exc).__name__,
                )
                logger.warning(f"idle_pause {line} error={exc!s}", extra=ex)
                return False
            stats.tombstoned += 1
            line, ex = idlep_bundle(
                event=IDLEP_EVENT_TOMBSTONED,
                source=IDLEP_SOURCE_SWEEPER,
                sandbox_id=candidate.sandbox_id,
                namespace=candidate.namespace,
                threshold_seconds=threshold,
            )
            logger.info(f"idle_pause {line}", extra=ex)
        if decision.verdict != IdleVerdict.IDLE:
            return False
        return True

    async def _issue_pause(
        self,
        candidate: SandboxCandidate,
        threshold: int,
        judged_at_ms: int,
        last_active_ms: Optional[int],
        stats: SweepStats,
    ) -> None:
        outcome = await asyncio.to_thread(self._executor.pause, candidate)
        if outcome == PauseOutcome.ACCEPTED:
            record_pause_request(outcome="accepted")
            stats.paused += 1
            observation_age = (
                "unknown"
                if last_active_ms is None
                else f"{max(0, judged_at_ms - last_active_ms) / 1000:.1f}s"
            )
            line, ex = idlep_bundle(
                event=IDLEP_EVENT_PAUSE_ISSUED,
                source=IDLEP_SOURCE_SWEEPER,
                sandbox_id=candidate.sandbox_id,
                namespace=candidate.namespace,
                threshold_seconds=threshold,
                last_observation_age=observation_age,
                tombstoned=bool(last_active_ms is None),
            )
            logger.info(f"idle_pause {line}", extra=ex)
        elif outcome in (PauseOutcome.STATE_CHANGED, PauseOutcome.NOT_FOUND):
            record_pause_request(outcome="gated")
            stats.gated += 1
            stats.details.append(f"{candidate.sandbox_id}:{outcome.value}")
        else:
            record_pause_request(outcome="failed")
            stats.failed += 1
            stats.details.append(f"{candidate.sandbox_id}:{outcome.value}")


async def start_idle_pause_sweeper(
    app_config: AppConfig,
    sandbox_service: object,
    *,
    namespace_resolver: Callable[[], Sequence[str]],
    redis_client: Optional[Redis] = None,
) -> Optional[IdlePauseSweeper]:
    """Build and start the sweeper, or return ``None`` when it must not run.

    Requires ``[idle_pause].enabled``, the fsb (kubernetes) runtime, and a
    Redis connection (malformed DSN degrades the same way — fail toward
    "not pausing"). A client created here is closed by the sweeper's
    ``stop()``; a caller-supplied client stays the caller's.
    """
    if not app_config.idle_pause.enabled:
        return None
    if app_config.runtime.type != "kubernetes":
        logger.info("idle_pause disabled for non-kubernetes runtime (fsb backend only)")
        return None

    fsb = None
    if isinstance(sandbox_service, CompositeSandboxService):
        fsb = sandbox_service.fsb_service
    elif isinstance(sandbox_service, FastSandboxService):
        fsb = sandbox_service
    if fsb is None:
        logger.warning("idle_pause enabled but no fsb backend is registered; sweeper not started")
        return None

    owned_redis = False
    if redis_client is None:
        try:
            redis_client = await connect_idle_pause_redis_from_config(app_config)
        except (RedisError, OSError, ValueError) as exc:
            logger.warning(f"idle_pause redis connect failed error={exc!s}; sweeper not started")
            return None
        owned_redis = redis_client is not None
        if redis_client is None:
            logger.info("idle_pause redis disabled; sweeper not started")
            return None

    ip = app_config.idle_pause
    sweeper = IdlePauseSweeper(
        namespace_resolver=namespace_resolver,
        inventory=FastSandboxInventory(fsb.cr_reader),
        activity=ActivityRegistry(redis_client, activity_ttl_seconds=ip.activity_ttl_seconds),
        locks=PauseLockManager(redis_client, lock_ttl_seconds=ip.redis.lock_ttl_seconds),
        executor=FastPathPauseExecutor(fsb.fastpath_client),
        sweep_interval_seconds=ip.sweep_interval_seconds,
        owned_redis=redis_client if owned_redis else None,
    )
    sweeper.start()
    logger.info(
        f"idle_pause sweeper started namespaces={list(dict.fromkeys(namespace_resolver()))} "
        f"sweep_interval={ip.sweep_interval_seconds} "
        f"activity_ttl={ip.activity_ttl_seconds}"
    )
    return sweeper
