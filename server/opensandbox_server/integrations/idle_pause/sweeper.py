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

"""Idle sweeper: the OSEP-0024 auto-pause loop (server side).

Multi-replica by design, no leader election: every replica sweeps on its own
timer and deduplication happens at the point of effect — the per-sandbox
``SET NX EX`` lock admits one replica per idle episode, and FastPath
``PauseSandbox`` is an idempotent CAS patch whose replay is harmless, so a
lost race converges to a single pause anyway.

Gate order (first failure drops the candidate silently for this sweep):
opt-in -> Running -> expiry -> idle (value / tombstone / unknown) -> probe
(a declared probe keeps the sandbox pause-exempt until the probe pipeline
lands) -> lock -> re-verify under lock -> PauseSandbox.

Fail-safe direction: any Redis failure skips the sweep entirely; every other
failure leaves the sandbox Running. The worst case of this subsystem is a
missed pause, never a lost sandbox.
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
        # Re-resolved every sweep: tenants hot-reload (file provider) and HTTP
        # providers may enumerate late, so a startup snapshot would strand
        # later-added tenants' sandboxes un-swept.
        self._namespace_resolver = namespace_resolver
        self._inventory = inventory
        self._activity = activity
        self._locks = locks
        self._executor = executor
        self._interval = float(sweep_interval_seconds)
        self._lock_owner = lock_owner or f"sweeper-{id(self):x}"
        self._clock = clock
        # Client lifecycle ownership: set only when this sweeper created the
        # client (see start_idle_pause_sweeper); a caller-supplied client
        # stays the caller's to close.
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
            await close_idle_pause_redis_client(self._owned_redis)
            self._owned_redis = None

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
            # Redis unreachable: skip entirely — fail toward "not pausing".
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

        # Gates 1-2 (opt-in, Running) and 3 (expiry) are pure candidate checks;
        # only survivors reach the shared Redis read.
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
            return False  # opt-in gate: absence of policy is a hard no-op
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

        # Gate 4: idle — pure function of the activity key and its tombstone.
        if not await self._decide(candidate, last_active_ms, now_ms, threshold, stats):
            return

        # Gate 7 (probe): a declared probe must veto busy sandboxes; until the
        # probe pipeline lands, declaring one keeps the sandbox pause-exempt
        # (fail toward "not pausing").
        if candidate.policy.active_probe is not None:
            record_pause_request(outcome="gated")
            stats.gated += 1
            stats.details.append(f"{candidate.sandbox_id}:active_probe_declared")
            return

        # Gate 5: per-sandbox admission lock.
        try:
            acquired = await self._locks.try_acquire(candidate.sandbox_id, self._lock_owner)
        except (RedisError, OSError) as exc:
            # Redis died between the batch read and the lock: drop this
            # candidate (fail toward "not pausing"), never raise past the
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
            # Gate 6: re-verify under lock — a request may have landed between
            # the batch read and the lock; a newer observation drops us.
            try:
                current = await self._activity.read(candidate.sandbox_id)
            except (RedisError, OSError) as exc:
                # Cannot re-verify: drop rather than pause on stale evidence.
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
            # Best-effort early release: the TTL is the primary release path,
            # so a Redis failure here must never mask the sweep's outcome.
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
            except (RedisError, OSError):
                return False  # Redis hiccup: drop this candidate, never pause
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
            except (RedisError, OSError):
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

    Guards: ``[idle_pause].enabled`` and the fsb (kubernetes) runtime must be
    on, and Redis must connect — activity tracking is load-bearing for pause
    decisions, so without it the sweeper never issues pauses (fail toward
    "not pausing"). A malformed DSN (``ValueError`` from the client builder)
    degrades the same way instead of crashing startup.

    When this factory creates the Redis client it also owns it: the
    sweeper's ``stop()`` closes it. A caller-supplied client stays the
    caller's responsibility.
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
