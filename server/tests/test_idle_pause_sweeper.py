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

"""Sweeper gate-order tests with in-memory collaborators.

FastPath / CR semantics are covered by the adapters' own units; here the
gates, the fail-safe directions, and the pause contract are under test.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

import pytest

from opensandbox_server.integrations.idle_pause.activity import (
    ActivityRegistry,
    unknown_tombstone_key,
)
from opensandbox_server.integrations.idle_pause.executor import PauseOutcome
from opensandbox_server.integrations.idle_pause.inventory import SandboxCandidate
from opensandbox_server.integrations.idle_pause.locking import PauseLockManager
from opensandbox_server.integrations.idle_pause.policy import (
    ActivityProbe,
    IdlePolicy,
    validate_idle_policy,
)
from opensandbox_server.integrations.idle_pause.sweeper import IdlePauseSweeper
from tests.test_idle_pause_activity import FakeAsyncRedis

NOW_MS = 1_000_000_000_000
X = 300


def _policy(**kwargs) -> IdlePolicy:
    return validate_idle_policy(idle_timeout_seconds=X, on_idle="pause", **kwargs)


def _candidate(
    sandbox_id: str = "fsb_1",
    *,
    state: str = "Running",
    policy: Optional[IdlePolicy] = None,
    expires_in: Optional[int] = 3600,
) -> SandboxCandidate:
    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=expires_in) if expires_in is not None else None
    )
    return SandboxCandidate(
        sandbox_id=sandbox_id,
        namespace="ns",
        uid="uid-1",
        generation=7,
        state=state,
        expires_at=expires_at,
        policy=policy,
    )


class FakeInventory:
    def __init__(self, candidates: list[SandboxCandidate]):
        self.candidates = candidates

    def snapshot(self, namespace: str) -> list[SandboxCandidate]:
        return list(self.candidates)


class FakeExecutor:
    def __init__(self, outcome: PauseOutcome = PauseOutcome.ACCEPTED):
        self.outcome = outcome
        self.calls: list[SandboxCandidate] = []

    def pause(self, candidate: SandboxCandidate) -> PauseOutcome:
        self.calls.append(candidate)
        return self.outcome


def _sweeper(
    candidates: list[SandboxCandidate],
    redis_client: FakeAsyncRedis,
    executor: FakeExecutor,
    *,
    clock_now: int = NOW_MS,
) -> IdlePauseSweeper:
    return IdlePauseSweeper(
        namespaces=["ns"],
        inventory=FakeInventory(candidates),
        activity=ActivityRegistry(redis_client, activity_ttl_seconds=1800),  # type: ignore[arg-type]
        locks=PauseLockManager(redis_client, lock_ttl_seconds=30),  # type: ignore[arg-type]
        executor=executor,  # type: ignore[arg-type]
        sweep_interval_seconds=15,
        clock=lambda: clock_now,
    )


@pytest.mark.asyncio
async def test_idle_by_value_issues_pause_with_idempotent_request_id():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)

    await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
        candidate.sandbox_id, now_ms=NOW_MS - (X + 10) * 1000
    )
    stats = await sweeper.sweep_once()

    assert len(executor.calls) == 1
    assert executor.calls[0].uid == candidate.uid
    assert executor.calls[0].generation == candidate.generation
    assert stats.paused == 1
    assert stats.gated == 0


@pytest.mark.asyncio
async def test_fresh_activity_never_pauses():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)
    await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
        candidate.sandbox_id, now_ms=NOW_MS - 1000
    )
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.paused == 0


@pytest.mark.asyncio
async def test_missing_key_creates_tombstone_then_pauses_once_aged():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)

    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.tombstoned == 1
    assert redis.store[unknown_tombstone_key(candidate.sandbox_id)] == str(NOW_MS)
    assert redis.ttls[unknown_tombstone_key(candidate.sandbox_id)] == 1800 + 15

    # Second sweep, tombstone younger than X: still unknown.
    sweeper_later = _sweeper(
        [candidate], redis, executor, clock_now=NOW_MS + (X - 10) * 1000
    )
    await sweeper_later.sweep_once()
    assert executor.calls == []

    # Tombstone aged >= X: idle, pause proceeds.
    sweeper_final = _sweeper(
        [candidate], redis, executor, clock_now=NOW_MS + (X + 1) * 1000
    )
    stats = await sweeper_final.sweep_once()
    assert len(executor.calls) == 1
    assert stats.paused == 1


@pytest.mark.asyncio
async def test_wake_only_policy_is_never_auto_paused():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=validate_idle_policy(idle_timeout_seconds=None))
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.opted_in == 0


@pytest.mark.asyncio
async def test_non_running_and_expired_are_skipped():
    redis = FakeAsyncRedis()
    paused = _candidate("fsb_paused", state="Paused", policy=_policy())
    resuming = _candidate("fsb_resuming", state="Resuming", policy=_policy())
    expired = _candidate("fsb_expired", policy=_policy(), expires_in=-1)
    executor = FakeExecutor()
    sweeper = _sweeper([paused, resuming, expired], redis, executor)
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.paused == 0
    assert stats.opted_in == 3


@pytest.mark.asyncio
async def test_lock_contention_gates_without_pause():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)
    await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
        candidate.sandbox_id, now_ms=NOW_MS - (X + 10) * 1000
    )
    await PauseLockManager(redis, lock_ttl_seconds=30).try_acquire(  # type: ignore[arg-type]
        candidate.sandbox_id, "other-replica"
    )
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.gated == 1


@pytest.mark.asyncio
async def test_activity_landing_between_read_and_lock_drops_candidate():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    registry = FakeSlippingRegistry(redis, slip_at_read=True)
    sweeper = IdlePauseSweeper(
        namespaces=["ns"],
        inventory=FakeInventory([candidate]),
        activity=registry,  # type: ignore[arg-type]
        locks=PauseLockManager(redis, lock_ttl_seconds=30),  # type: ignore[arg-type]
        executor=executor,  # type: ignore[arg-type]
        sweep_interval_seconds=15,
        clock=lambda: NOW_MS,
    )
    await registry.record(candidate.sandbox_id, now_ms=NOW_MS - (X + 5) * 1000)
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.gated >= 1


class FakeSlippingRegistry:
    """Activity registry whose re-verify read observes a newer write."""

    def __init__(self, redis: FakeAsyncRedis, slip_at_read: bool):
        self._inner = ActivityRegistry(redis, activity_ttl_seconds=1800)  # type: ignore[arg-type]
        self._slip = slip_at_read
        self._slipped = False

    async def record(self, *args, **kwargs):
        await self._inner.record(*args, **kwargs)

    async def ping(self):
        await self._inner.ping()

    async def read_many(self, ids):
        return await self._inner.read_many(ids)

    async def read(self, sandbox_id: str):
        value = await self._inner.read(sandbox_id)
        if self._slip and not self._slipped:
            self._slipped = True
            return (value or 0) + 1  # a request landed meanwhile
        return value

    async def read_tombstone(self, sandbox_id: str):
        return await self._inner.read_tombstone(sandbox_id)

    async def ensure_tombstone(self, *args, **kwargs):
        await self._inner.ensure_tombstone(*args, **kwargs)

    async def clear_tombstone(self, sandbox_id: str):
        await self._inner.clear_tombstone(sandbox_id)


@pytest.mark.asyncio
async def test_declared_probe_gates_pause_until_probe_pipeline_lands():
    redis = FakeAsyncRedis()
    probe = ActivityProbe(port=8080, path="/active", timeout_seconds=2)
    candidate = _candidate(policy=_policy(active_probe=probe))
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)
    await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
        candidate.sandbox_id, now_ms=NOW_MS - (X + 10) * 1000
    )
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.gated == 1


@pytest.mark.asyncio
async def test_pause_state_changed_counts_as_gated_not_failed():
    redis = FakeAsyncRedis()
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor(outcome=PauseOutcome.STATE_CHANGED)
    sweeper = _sweeper([candidate], redis, executor)
    await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
        candidate.sandbox_id, now_ms=NOW_MS - (X + 10) * 1000
    )
    stats = await sweeper.sweep_once()
    assert stats.gated == 1
    assert stats.failed == 0


@pytest.mark.asyncio
async def test_redis_unreachable_skips_sweep_entirely():
    redis = FakeAsyncRedis(fail=True)
    candidate = _candidate(policy=_policy())
    executor = FakeExecutor()
    sweeper = _sweeper([candidate], redis, executor)
    stats = await sweeper.sweep_once()
    assert executor.calls == []
    assert stats.candidates == 0


@pytest.mark.asyncio
async def test_pause_issued_audit_line_carries_threshold_and_age():
    class Capture(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.records: list[logging.LogRecord] = []

        def emit(self, record: logging.LogRecord) -> None:
            self.records.append(record)

    # configure_logging sets the opensandbox_server logger propagate=False,
    # so records must be captured at the module logger itself.
    handler = Capture()
    sweeper_logger = logging.getLogger(
        "opensandbox_server.integrations.idle_pause.sweeper"
    )
    sweeper_logger.addHandler(handler)
    try:
        redis = FakeAsyncRedis()
        candidate = _candidate(policy=_policy())
        executor = FakeExecutor()
        sweeper = _sweeper([candidate], redis, executor)
        await ActivityRegistry(redis, activity_ttl_seconds=1800).record(  # type: ignore[arg-type]
            candidate.sandbox_id, now_ms=NOW_MS - (X + 10) * 1000
        )
        await sweeper.sweep_once()
    finally:
        sweeper_logger.removeHandler(handler)

    records = [r for r in handler.records if getattr(r, "idlep_event", None) == "pause_issued"]
    assert len(records) == 1
    record = records[0]
    assert record.idlep_sandbox_id == candidate.sandbox_id  # type: ignore[attr-defined]
    assert record.idlep_threshold_seconds == X  # type: ignore[attr-defined]
    assert record.idlep_last_observation_age == "310.0s"  # type: ignore[attr-defined]
    assert record.idlep_tombstoned is False  # type: ignore[attr-defined]
