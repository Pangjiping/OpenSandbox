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
"""Asyncio sandbox pool implementation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import timedelta

from opensandbox._async_pool_reconciler import run_async_reconcile_tick
from opensandbox._async_pool_store import InMemoryAsyncPoolStateStore
from opensandbox._pool_reconciler import ReconcileState
from opensandbox.config import ConnectionConfig
from opensandbox.exceptions import (
    PoolAcquireFailedException,
    PoolDestroyedException,
    PoolEmptyException,
    PoolNotRunningException,
    PoolStateStoreUnavailableException,
)
from opensandbox.internal.readiness import ReadinessBudget
from opensandbox.manager import SandboxManager
from opensandbox.pool_types import (
    AcquirePolicy,
    AsyncPoolConfig,
    AsyncPooledSandboxCreator,
    AsyncPoolStateStore,
    IdleEntry,
    PoolCreationSpec,
    PoolDestroyState,
    PooledSandboxCreateContext,
    PooledSandboxCreateReason,
    PoolLifecycleState,
    PoolSnapshot,
    PoolState,
    effective_max_idle_attempts,
    policy_falls_through_to_direct_create,
)
from opensandbox.pool_types import (
    try_take_idle_with_min_ttl_async as _try_take_idle_with_min_ttl_async,
)
from opensandbox.sandbox import Sandbox

logger = logging.getLogger(__name__)

_WARMUP_TERMINATION_TIMEOUT_SECONDS = 5.0
_RELEASE_ALL_IDLE_CONCURRENCY = 50


class SandboxPoolAsync:
    """Client-side asyncio sandbox pool aligned with Kotlin SandboxPool."""

    def __init__(
        self,
        *,
        pool_name: str,
        max_idle: int,
        state_store: AsyncPoolStateStore,
        connection_config: ConnectionConfig,
        creation_spec: PoolCreationSpec,
        owner_id: str | None = None,
        warmup_concurrency: int | None = None,
        primary_lock_ttl: timedelta = timedelta(seconds=60),
        reconcile_interval: timedelta = timedelta(seconds=30),
        degraded_threshold: int = 3,
        acquire_ready_timeout: timedelta = timedelta(seconds=30),
        acquire_health_check_polling_interval: timedelta = timedelta(milliseconds=200),
        acquire_health_check: Callable[[Sandbox], Awaitable[bool]] | None = None,
        acquire_skip_health_check: bool = False,
        warmup_ready_timeout: timedelta = timedelta(seconds=30),
        warmup_health_check_polling_interval: timedelta = timedelta(milliseconds=200),
        warmup_health_check: Callable[[Sandbox], Awaitable[bool]] | None = None,
        warmup_sandbox_preparer: Callable[[Sandbox], Awaitable[None]] | None = None,
        warmup_skip_health_check: bool = False,
        warmup_create_qps: int = 10,
        warmup_post_prepare_health_check: Callable[[Sandbox], Awaitable[bool]]
        | None = None,
        warmup_post_prepare_health_check_timeout: timedelta = timedelta(seconds=30),
        idle_timeout: timedelta = timedelta(hours=24),
        drain_timeout: timedelta = timedelta(seconds=30),
        acquire_min_remaining_ttl: timedelta | None = None,
        max_acquire_retries: int = 3,
        sandbox_manager_factory: Callable[
            [ConnectionConfig], Awaitable[SandboxManager]
        ] = SandboxManager.create,
        sandbox_factory: type[Sandbox] = Sandbox,
        sandbox_creator: AsyncPooledSandboxCreator | None = None,
    ) -> None:
        self._config = AsyncPoolConfig(
            pool_name=pool_name,
            owner_id=owner_id,
            max_idle=max_idle,
            warmup_concurrency=warmup_concurrency,
            primary_lock_ttl=primary_lock_ttl,
            state_store=state_store,
            connection_config=connection_config,
            creation_spec=creation_spec,
            reconcile_interval=reconcile_interval,
            degraded_threshold=degraded_threshold,
            acquire_ready_timeout=acquire_ready_timeout,
            acquire_health_check_polling_interval=acquire_health_check_polling_interval,
            acquire_health_check=acquire_health_check,
            acquire_skip_health_check=acquire_skip_health_check,
            warmup_ready_timeout=warmup_ready_timeout,
            warmup_health_check_polling_interval=warmup_health_check_polling_interval,
            warmup_health_check=warmup_health_check,
            warmup_sandbox_preparer=warmup_sandbox_preparer,
            warmup_skip_health_check=warmup_skip_health_check,
            warmup_create_qps=warmup_create_qps,
            warmup_post_prepare_health_check=warmup_post_prepare_health_check,
            warmup_post_prepare_health_check_timeout=warmup_post_prepare_health_check_timeout,
            idle_timeout=idle_timeout,
            drain_timeout=drain_timeout,
            acquire_min_remaining_ttl=acquire_min_remaining_ttl,
            sandbox_creator=sandbox_creator,
            max_acquire_retries=max_acquire_retries,
        )
        self._state_store = self._config.state_store
        self._connection_config = connection_config
        self._creation_spec = creation_spec
        self._sandbox_manager_factory = sandbox_manager_factory
        self._sandbox_factory = sandbox_factory
        self._reconcile_state = ReconcileState(degraded_threshold)
        self._current_max_idle = max_idle
        self._lifecycle_state = PoolLifecycleState.NOT_STARTED
        self._lifecycle_lock = asyncio.Lock()
        self._reconcile_lock = asyncio.Lock()
        self._in_flight = 0
        self._in_flight_condition = asyncio.Condition()
        self._stop_event = asyncio.Event()
        self._scheduler_task: asyncio.Task[None] | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._primary_owned = False
        # Leadership generation, bumped on every primary gained/lost transition.
        # Warmups admitted under an older epoch are fenced at renew/commit time, so a
        # stale warmup cannot publish after this node lost and reacquired the lease
        # (mirrors the Kotlin leaderEpoch fence).
        self._leader_epoch = 0
        self._warming_count = 0
        # Bounds concurrent warmup work (create + readiness + prepare + renew),
        # mirroring the Kotlin warmup executor's worker cap. Admission (QPS) is
        # bounded separately by warmup_create_qps in the reconcile plan.
        self._warmup_slots = asyncio.Semaphore(
            max(1, int(self._config.warmup_concurrency or 1))
        )
        self._sandbox_manager: SandboxManager | None = None
        self._warmup_tasks: set[asyncio.Task[str | None]] = set()

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if self._lifecycle_state in (
                PoolLifecycleState.RUNNING,
                PoolLifecycleState.STARTING,
            ):
                return
            self._lifecycle_state = PoolLifecycleState.STARTING
            try:
                await self._ensure_pool_namespace_active()
                self._warn_if_primary_lock_ttl_may_expire_during_warmup()
                self._sandbox_manager = await self._create_sandbox_manager()
                await self._state_store.set_idle_entry_ttl(
                    self._config.pool_name, self._config.idle_timeout
                )
                await self._state_store.set_max_idle(
                    self._config.pool_name, self._config.max_idle
                )
                stop_event = asyncio.Event()
                self._stop_event = stop_event
                self._lifecycle_state = PoolLifecycleState.RUNNING
                self._scheduler_task = asyncio.create_task(
                    self._run_scheduler(stop_event),
                    name=f"sandbox-pool-reconcile-{self._config.pool_name}",
                )
                # Aligned with the Kotlin SDK: renew the primary lease independently of
                # reconcile work, at an interval no greater than one third of the TTL.
                self._heartbeat_task = asyncio.create_task(
                    self._run_primary_heartbeat(stop_event),
                    name=f"sandbox-pool-heartbeat-{self._config.pool_name}",
                )
            except Exception:
                await self._stop_reconcile(wait_for_warmup=True)
                await self._close_provider()
                self._lifecycle_state = PoolLifecycleState.STOPPED
                raise

    async def acquire(
        self,
        sandbox_timeout: timedelta | None = None,
        policy: AcquirePolicy = AcquirePolicy.DIRECT_CREATE,
    ) -> Sandbox:
        if self._lifecycle_state != PoolLifecycleState.RUNNING:
            state = self._lifecycle_state
            await self._raise_if_pool_namespace_destroyed()
            raise PoolNotRunningException(
                f"Cannot acquire when pool state is {state.value}"
            )
        await self._begin_operation()
        try:
            if self._lifecycle_state != PoolLifecycleState.RUNNING:
                state = self._lifecycle_state
                await self._raise_if_pool_namespace_destroyed()
                raise PoolNotRunningException(
                    f"Cannot acquire when pool state is {state.value}"
                )
            await self._ensure_pool_namespace_active_for_acquire(policy)
            pool_name = self._config.pool_name
            max_attempts = effective_max_idle_attempts(
                policy, self._config.max_acquire_retries
            )

            pending_kill: list[str] = []
            last_sandbox_id: str | None = None
            last_idle_connect_failure: Exception | None = None
            attempted_any = False
            loop_exhausted = True
            attempt = 0
            while attempt < max_attempts:
                attempt += 1
                try:
                    take_result = await _try_take_idle_with_min_ttl_async(
                        self._state_store,
                        pool_name,
                        self._config.acquire_min_remaining_ttl,
                    )
                except PoolStateStoreUnavailableException:
                    # State store outage. Per OSEP-0005, under policies that fall through to
                    # direct-create on empty idle we degrade to that fallback so the pool stays
                    # at least as available as raw SDK usage during store outages.
                    if not policy_falls_through_to_direct_create(policy):
                        self._schedule_kill_discarded_alive(
                            pool_name, tuple(pending_kill), source="acquire"
                        )
                        raise
                    logger.warning(
                        "acquire: state store unavailable, falling through to direct create "
                        "per policy=%s",
                        policy.value,
                    )
                    loop_exhausted = False
                    break
                if take_result.discarded_alive_sandbox_ids:
                    pending_kill.extend(take_result.discarded_alive_sandbox_ids)
                sandbox_id = take_result.sandbox_id
                if sandbox_id is None:
                    loop_exhausted = False
                    break
                last_sandbox_id = sandbox_id
                attempted_any = True
                try:
                    sandbox = await self._sandbox_factory.connect(
                        sandbox_id,
                        connection_config=self._connection_for_pool_resource(),
                        health_check=self._config.acquire_health_check,
                        connect_timeout=self._config.acquire_ready_timeout,
                        health_check_polling_interval=(
                            self._config.acquire_health_check_polling_interval
                        ),
                        skip_health_check=self._config.acquire_skip_health_check,
                    )
                except PoolDestroyedException:
                    self._schedule_kill_discarded_alive(
                        pool_name, tuple(pending_kill), source="acquire"
                    )
                    raise
                except Exception as exc:
                    # Connect / readiness / health-check failure — the idle candidate itself
                    # is unusable. Remove it, fire-and-forget the remote kill so a slow DELETE
                    # (up to the lifecycle client's request_timeout, 30s by default) does not
                    # block the next retry iteration, then let the loop try the next candidate.
                    last_idle_connect_failure = exc
                    await self._state_store.remove_idle(pool_name, sandbox_id)
                    self._schedule_kill_discarded_alive(
                        pool_name, (sandbox_id,), source="acquire-stale"
                    )
                    if self._lifecycle_state != PoolLifecycleState.RUNNING:
                        state = self._lifecycle_state
                        await self._raise_if_pool_namespace_destroyed()
                        self._schedule_kill_discarded_alive(
                            pool_name, tuple(pending_kill), source="acquire"
                        )
                        raise PoolNotRunningException(
                            f"Cannot acquire when pool state is {state.value}"
                        ) from exc
                    await self._ensure_pool_namespace_active()
                    continue
                # Connect + readiness succeeded. From here on the sandbox is a healthy,
                # borrowable idle: any failure below (renew rejection, namespace fenced) is
                # NOT a candidate-specific problem, so we must not treat it as "stale idle"
                # and burn another retry. Dispose the sandbox and surface the error.
                try:
                    if sandbox_timeout is not None:
                        await sandbox.renew(sandbox_timeout)
                    await self._ensure_pool_namespace_active_after_create(sandbox)
                except PoolDestroyedException:
                    self._schedule_kill_discarded_alive(
                        pool_name, tuple(pending_kill), source="acquire"
                    )
                    raise
                except Exception as exc:
                    # Renew failed against a healthy sandbox. try_take_idle already popped this
                    # id out of the store; a bare close() would only release local resources and
                    # leave the remote sandbox alive-but-untracked until its server-side TTL
                    # expires. Kill it best-effort, then close local resources and re-raise.
                    logger.warning(
                        "Acquire renew failed after idle connect; killing remote sandbox and "
                        "not retrying (renew errors are not candidate-specific): "
                        "pool_name=%s sandbox_id=%s policy=%s error=%s",
                        pool_name,
                        sandbox_id,
                        policy.value,
                        exc,
                    )
                    try:
                        await sandbox.kill()
                    except Exception as kill_exc:
                        logger.warning(
                            "Best-effort kill after renew failure failed: "
                            "pool_name=%s sandbox_id=%s error=%s",
                            pool_name,
                            sandbox_id,
                            kill_exc,
                        )
                    try:
                        await sandbox.close()
                    except Exception as close_exc:
                        # Best-effort local resource release; original renew error must be the
                        # one that surfaces, so log at debug and continue with the raise below.
                        logger.debug(
                            "Best-effort close after renew failure failed: "
                            "pool_name=%s sandbox_id=%s error=%s",
                            pool_name,
                            sandbox_id,
                            close_exc,
                        )
                    self._schedule_kill_discarded_alive(
                        pool_name, tuple(pending_kill), source="acquire"
                    )
                    raise
                self._schedule_kill_discarded_alive(
                    pool_name, tuple(pending_kill), source="acquire"
                )
                return sandbox

            self._schedule_kill_discarded_alive(
                pool_name, tuple(pending_kill), source="acquire"
            )

            if not attempted_any:
                reason = "idle buffer empty"
            elif loop_exhausted:
                reason = (
                    f"idle connect failed for {max_attempts} candidate(s); "
                    f"last sandbox_id={last_sandbox_id} (stale or unreachable)"
                )
            else:
                reason = (
                    f"idle connect failed for sandbox_id={last_sandbox_id}; "
                    f"idle buffer drained before reaching max_acquire_retries={max_attempts}"
                )
            if not policy_falls_through_to_direct_create(policy):
                if attempted_any:
                    raise PoolAcquireFailedException(
                        f"Cannot acquire: {reason}; policy is {policy.value}",
                        last_idle_connect_failure,
                    )
                raise PoolEmptyException(
                    f"Cannot acquire: {reason}; policy is {policy.value}"
                )
            return await self._direct_create(sandbox_timeout, policy=policy)
        finally:
            await self._end_operation()

    async def resize(self, max_idle: int) -> None:
        if max_idle < 0:
            raise ValueError("max_idle must be >= 0")
        await self._ensure_pool_namespace_active()
        await self._state_store.set_max_idle(self._config.pool_name, max_idle)
        self._current_max_idle = max_idle

    async def release_all_idle(self) -> int:
        pool_name = self._config.pool_name
        count = 0
        temporary_manager: SandboxManager | None = None
        try:
            while True:
                sandbox_id = await self._state_store.try_take_idle(pool_name)
                if sandbox_id is None:
                    break
                count += 1
                try:
                    manager = self._sandbox_manager or temporary_manager
                    if manager is None:
                        manager = await self._create_sandbox_manager()
                        temporary_manager = manager
                    await manager.kill_sandbox(sandbox_id)
                except Exception as exc:
                    logger.warning(
                        f"release_all_idle: failed to kill sandbox: pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
                    )
        finally:
            if temporary_manager is not None:
                await temporary_manager.close()
        return count

    async def release_all_idle_parallel(
        self, max_workers: int = _RELEASE_ALL_IDLE_CONCURRENCY
    ) -> int:
        if max_workers <= 0:
            raise ValueError("max_workers must be positive")

        cleanup_task = asyncio.create_task(self._release_all_idle_parallel(max_workers))
        cancellation: asyncio.CancelledError | None = None
        cleanup_failure: BaseException | None = None
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError as exc:
                cancellation = cancellation or exc
            except BaseException as exc:
                cleanup_failure = exc

        if cancellation is not None:
            if cleanup_failure is None and cleanup_task.done():
                try:
                    cleanup_failure = cleanup_task.exception()
                except asyncio.CancelledError:
                    pass
            if cleanup_failure is not None:
                raise cancellation from cleanup_failure
            raise cancellation
        if cleanup_failure is not None:
            raise cleanup_failure
        return cleanup_task.result()

    async def _release_all_idle_parallel(self, max_workers: int) -> int:
        pool_name = self._config.pool_name
        sandbox_ids: list[str] = []
        drain_error: Exception | None = None
        temporary_manager: SandboxManager | None = None
        try:
            while True:
                try:
                    sandbox_id = await self._state_store.try_take_idle(pool_name)
                except Exception as exc:
                    drain_error = exc
                    break
                if sandbox_id is None:
                    break
                sandbox_ids.append(sandbox_id)

            if sandbox_ids:
                manager = self._sandbox_manager
                if manager is None:
                    try:
                        manager = await self._create_sandbox_manager()
                        temporary_manager = manager
                    except Exception as exc:
                        logger.warning(
                            f"release_all_idle_parallel: failed to create sandbox manager; draining idle ids without remote kill: pool_name={pool_name} error={exc}"
                        )

                semaphore = asyncio.Semaphore(max_workers)

                async def kill(sandbox_id: str) -> None:
                    if manager is None:
                        return
                    async with semaphore:
                        try:
                            await manager.kill_sandbox(sandbox_id)
                        except Exception as exc:
                            logger.warning(
                                f"release_all_idle_parallel: failed to kill sandbox: pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
                            )

                await asyncio.gather(*(kill(sandbox_id) for sandbox_id in sandbox_ids))
        finally:
            if temporary_manager is not None:
                await temporary_manager.close()
        if drain_error is not None:
            raise drain_error
        return len(sandbox_ids)

    async def snapshot(self) -> PoolSnapshot:
        lifecycle_state = self._lifecycle_state
        if lifecycle_state in (
            PoolLifecycleState.NOT_STARTED,
            PoolLifecycleState.STOPPED,
        ):
            state = PoolState.STOPPED
        elif lifecycle_state == PoolLifecycleState.DRAINING:
            state = PoolState.DRAINING
        else:
            state = self._reconcile_state.state
        counters = await self._state_store.snapshot_counters(self._config.pool_name)
        return PoolSnapshot(
            state=state,
            lifecycle_state=lifecycle_state,
            idle_count=counters.idle_count,
            max_idle=await self._resolve_max_idle(),
            failure_count=self._reconcile_state.failure_count,
            backoff_active=self._reconcile_state.is_backoff_active(),
            last_error=self._reconcile_state.last_error,
            in_flight_operations=self._in_flight,
        )

    async def snapshot_idle_entries(self) -> list[IdleEntry]:
        return await self._state_store.snapshot_idle_entries(self._config.pool_name)

    async def shutdown(self, graceful: bool = True) -> None:
        async with self._lifecycle_lock:
            if self._lifecycle_state == PoolLifecycleState.STOPPED:
                return
            if not graceful:
                await self._stop_reconcile(wait_for_warmup=False)
                self._lifecycle_state = PoolLifecycleState.STOPPED
                await self._close_provider()
                return
            self._lifecycle_state = PoolLifecycleState.DRAINING
            await self._stop_reconcile(wait_for_warmup=False, join_scheduler=False)
        drained = await self._await_in_flight_drain(self._config.drain_timeout)
        if not drained:
            logger.warning(
                f"Async pool graceful shutdown timed out waiting in-flight operations: pool_name={self._config.pool_name} in_flight={self._in_flight} timeout_ms={int(self._config.drain_timeout.total_seconds() * 1000)}"
            )
        async with self._lifecycle_lock:
            self._lifecycle_state = PoolLifecycleState.STOPPED
            await self._close_provider()

    async def __aenter__(self) -> SandboxPoolAsync:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        await self.shutdown(graceful=True)

    async def _run_scheduler(self, stop_event: asyncio.Event) -> None:
        initial_delay = (
            0
            if self._config.max_idle > 0
            else self._config.reconcile_interval.total_seconds()
        )
        if initial_delay > 0:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=initial_delay)
                return
            except (asyncio.TimeoutError, TimeoutError):
                pass
        while not stop_event.is_set():
            await self._run_reconcile_tick()
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self._config.reconcile_interval.total_seconds(),
                )
                break
            except (asyncio.TimeoutError, TimeoutError):
                continue

    async def _run_reconcile_tick(self) -> None:
        if self._lifecycle_state != PoolLifecycleState.RUNNING:
            return
        async with self._reconcile_lock:
            if self._lifecycle_state != PoolLifecycleState.RUNNING:
                return
            await self._begin_operation()
            try:
                if self._lifecycle_state != PoolLifecycleState.RUNNING:
                    return
                if (
                    await self._state_store.get_destroy_state(self._config.pool_name)
                    != PoolDestroyState.ACTIVE
                ):
                    await self._stop_after_pool_namespace_destroyed()
                    return
                try:
                    # on_primary_acquired fires inside the tick, before warmup
                    # admission, so admitted tasks carry the current epoch.
                    if not await run_async_reconcile_tick(
                        config=self._config.with_max_idle(
                            await self._resolve_max_idle()
                        ),
                        state_store=self._state_store,
                        on_discard_sandbox=self._discard_sandbox_callback,
                        submit_warmups=self._submit_warmups,
                        on_primary_acquired=self._mark_primary_acquired,
                        warming_count=self._warming_count,
                    ):
                        self._mark_primary_lost()
                except Exception:
                    self._mark_primary_lost()
                    raise
            except Exception as exc:
                logger.error(
                    f"Async pool reconcile tick failed unexpectedly: pool_name={self._config.pool_name}",
                    exc_info=exc,
                )
            finally:
                await self._end_operation()

    async def _run_primary_heartbeat(self, stop_event: asyncio.Event) -> None:
        """Renew the primary lock independently of reconcile ticks.

        Aligned with the Kotlin SDK: the interval is ``min(reconcile_interval,
        primary_lock_ttl / 3)`` so a long reconcile cadence cannot let the lease
        expire. The heartbeat only renews while this node is the current primary;
        a failed renewal clears ownership until the next tick re-acquires it.
        """
        interval = min(
            self._config.reconcile_interval.total_seconds(),
            self._config.primary_lock_ttl.total_seconds() / 3,
        )
        while not stop_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
                return
            except (asyncio.TimeoutError, TimeoutError):
                pass
            if not self._primary_owned:
                continue
            try:
                renewed = await self._state_store.renew_primary_lock(
                    self._config.pool_name,
                    str(self._config.owner_id),
                    self._config.primary_lock_ttl,
                )
            except Exception as exc:
                # Keep periodic heartbeats alive after transient store failures.
                logger.error(
                    f"Pool primary heartbeat failed: pool_name={self._config.pool_name}",
                    exc_info=exc,
                )
                continue
            if not renewed:
                self._mark_primary_lost()
                logger.debug(
                    "Pool primary heartbeat skipped (not current owner): "
                    f"pool_name={self._config.pool_name} owner_id={self._config.owner_id}"
                )

    def _mark_primary_acquired(self) -> None:
        """Become the primary; bumps the leadership epoch (Kotlin markPrimaryAcquired)."""
        if not self._primary_owned:
            self._primary_owned = True
            self._leader_epoch += 1

    def _mark_primary_lost(self) -> None:
        """Lose the primary; bumps the leadership epoch (Kotlin markPrimaryLost).

        Warmups admitted under an older epoch are fenced at renew/commit time, so
        they cannot publish across a lease loss even if this node reacquires the
        lock with the same owner id.
        """
        if self._primary_owned:
            self._primary_owned = False
            self._leader_epoch += 1

    def _leader_epoch_is_current(self, leader_epoch: int) -> bool:
        return leader_epoch == self._leader_epoch

    def _submit_warmups(self, count: int) -> None:
        """Admit ``count`` warmup tasks and return immediately.

        Aligned with the Kotlin SDK's admission model: the reconcile tick only
        plans and admits; each admitted task then creates, validates, renews, and
        commits its sandbox independently of the tick. The warming counter is
        incremented synchronously here (before any task can start) so the next
        tick's deficit calculation already accounts for these admissions, and each
        task captures the current leadership epoch for commit fencing.
        """
        if count <= 0:
            return
        if self._lifecycle_state != PoolLifecycleState.RUNNING:
            return
        leader_epoch = self._leader_epoch
        for _ in range(count):
            self._warming_count += 1
            task = asyncio.create_task(self._run_warmup_task(leader_epoch))
            self._warmup_tasks.add(task)  # type: ignore[arg-type]
            task.add_done_callback(self._on_warmup_task_done)

    def _on_warmup_task_done(self, task: asyncio.Task[str | None]) -> None:
        self._warming_count -= 1
        self._warmup_tasks.discard(task)

    async def _run_warmup_task(self, leader_epoch: int) -> str | None:
        """One admitted warmup: create → validate → renew → commit.

        Runs detached from the reconcile tick inside a warmup slot, so
        ``warmup_concurrency`` bounds the whole pipeline including the create
        call (whose inline readiness loop is the expensive part). The captured
        ``leader_epoch`` fences the task across lease transitions: if this node
        lost and reacquired the primary lock while the warmup ran, the sandbox is
        dropped and killed instead of published. Committing renews the primary
        lock first (a lost lease drops and kills the sandbox, mirroring the
        Kotlin leader-epoch commit fence) and then publishes the ID to the idle
        store. Failures are recorded on the reconcile state; cancellation and
        leadership drops are not.
        """
        await self._begin_operation()
        try:
            await self._ensure_pool_namespace_active()
            sandbox: Sandbox | None = None
            try:
                async with self._warmup_slots:
                    sandbox = await self._build_warmup_sandbox()
                    if self._config.warmup_sandbox_preparer is not None:
                        await self._config.warmup_sandbox_preparer(sandbox)
                    await self._wait_post_prepare_healthy(sandbox)
                    if (
                        self._lifecycle_state != PoolLifecycleState.RUNNING
                        or not self._leader_epoch_is_current(leader_epoch)
                    ):
                        try:
                            await sandbox.kill()
                        except Exception:
                            pass
                        return None
                    # The server-side TTL has been ticking since sandbox creation;
                    # readiness wait and `warmup_sandbox_preparer` can both consume
                    # meaningful time. Renew right before committing so the store's
                    # stamped expiry actually matches what the server will honor —
                    # otherwise `acquire_min_remaining_ttl` overestimates remaining
                    # TTL by the warmup duration.
                    await sandbox.renew(self._config.idle_timeout)
                await self._ensure_pool_namespace_active_after_create(sandbox)
                return await self._commit_warmup_sandbox(sandbox, leader_epoch)
            except BaseException:
                if sandbox is not None:
                    try:
                        await sandbox.kill()
                    except Exception:
                        pass
                raise
            finally:
                if sandbox is not None:
                    await sandbox.close()
        except asyncio.CancelledError:
            # Shutdown cancellation is not a warmup failure.
            raise
        except Exception as exc:
            self._reconcile_state.record_failure(str(exc))
            return None
        finally:
            await self._end_operation()

    async def _commit_warmup_sandbox(
        self, sandbox: Sandbox, leader_epoch: int
    ) -> str | None:
        """Commit a renewed warmup sandbox to the idle buffer.

        Two fences apply before publishing, mirroring the Kotlin commit path: the
        captured leadership epoch must still be current (the lease was not lost
        and reacquired while this warmup ran), and the primary lock renewal must
        succeed. Otherwise the sandbox is killed instead of committed. Leadership
        drops are not recorded as failures (Kotlin counts them as DROPPED, not
        FAILURE).
        """
        pool_name = self._config.pool_name
        owner_id = str(self._config.owner_id)
        ttl = self._config.primary_lock_ttl
        sandbox_id = sandbox.id
        if not self._leader_epoch_is_current(leader_epoch):
            logger.warning(
                "Warmup commit dropped (leadership epoch changed): "
                f"pool_name={pool_name} sandbox_id={sandbox_id} "
                f"admitted_epoch={leader_epoch} current_epoch={self._leader_epoch}"
            )
            try:
                await sandbox.kill()
            except Exception as exc:
                logger.warning(
                    "Best-effort kill after epoch fence failed: "
                    f"pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
                )
            return None
        try:
            lock_renewed = await self._state_store.renew_primary_lock(
                pool_name, owner_id, ttl
            )
        except Exception as exc:
            logger.warning(
                "Warmup commit dropped (primary lock renewal failed): "
                f"pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
            )
            lock_renewed = False
        if not lock_renewed:
            try:
                await sandbox.kill()
            except Exception as exc:
                logger.warning(
                    "Best-effort kill after lost primary lock failed: "
                    f"pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
                )
            return None
        try:
            await self._state_store.put_idle(pool_name, sandbox_id)
        except Exception as exc:
            logger.warning(
                f"Warmup commit failed; dropped newly created sandbox: "
                f"pool_name={pool_name} sandbox_id={sandbox_id} error={exc}"
            )
            try:
                await self._state_store.remove_idle(pool_name, sandbox_id)
            except Exception:
                pass
            try:
                await sandbox.kill()
            except Exception as kill_exc:
                logger.warning(
                    "Best-effort kill after failed commit failed: "
                    f"pool_name={pool_name} sandbox_id={sandbox_id} error={kill_exc}"
                )
            self._reconcile_state.record_failure(f"warmup commit failed: {exc}")
            return None
        self._reconcile_state.record_success()
        return sandbox_id

    async def _wait_post_prepare_healthy(self, sandbox: Sandbox) -> None:
        """Re-validate readiness after the warmup preparer, if configured.

        Aligned with the Kotlin SDK's ``warmupPostPrepareHealthCheck`` stage: poll the
        caller-provided check at ``warmup_health_check_polling_interval`` until it
        returns True or ``warmup_post_prepare_health_check_timeout`` elapses. The
        preparer is never rerun; a timeout raises :class:`SandboxReadyTimeoutException`
        so the surrounding warmup failure path kills the sandbox.
        """
        check = self._config.warmup_post_prepare_health_check
        if check is None:
            return
        budget = ReadinessBudget(
            self._config.warmup_post_prepare_health_check_timeout,
            self._config.warmup_health_check_polling_interval,
        )
        await budget.health(lambda: check(sandbox), context="post-prepare health check")

    async def _build_warmup_sandbox(self) -> Sandbox:
        if self._config.sandbox_creator is not None:
            return await self._build_sandbox_from_creator(
                creator=self._config.sandbox_creator,
                reason=PooledSandboxCreateReason.WARMUP,
                ready_timeout=self._config.warmup_ready_timeout,
                health_check_polling_interval=self._config.warmup_health_check_polling_interval,
                skip_health_check=self._config.warmup_skip_health_check,
                health_check=self._config.warmup_health_check,
            )

        spec = self._creation_spec
        return await self._sandbox_factory.create(
            spec.image,
            timeout=self._config.idle_timeout,
            ready_timeout=self._config.warmup_ready_timeout,
            env=spec.env,
            metadata=spec.metadata,
            resource=spec.resource,
            network_policy=spec.network_policy,
            platform=spec.platform,
            extensions=spec.extensions,
            secure_access=spec.secure_access,
            entrypoint=spec.entrypoint,
            volumes=spec.volumes,
            connection_config=self._connection_for_pool_resource(),
            health_check=self._config.warmup_health_check,
            health_check_polling_interval=self._config.warmup_health_check_polling_interval,
            skip_health_check=self._config.warmup_skip_health_check,
        )

    async def _direct_create(
        self,
        sandbox_timeout: timedelta | None,
        policy: AcquirePolicy = AcquirePolicy.DIRECT_CREATE,
    ) -> Sandbox:
        # policy-aware namespace check: if the state store is down and the policy is a
        # fallthrough one, treat destroy-state as unknown and proceed to direct-create
        # instead of surfacing the outage. See _ensure_pool_namespace_active_for_acquire
        # for the full rationale.
        await self._ensure_pool_namespace_active_for_acquire(policy)
        if self._config.sandbox_creator is not None:
            sandbox = await self._build_sandbox_from_creator(
                creator=self._config.sandbox_creator,
                reason=PooledSandboxCreateReason.DIRECT_CREATE,
                ready_timeout=self._config.acquire_ready_timeout,
                health_check_polling_interval=self._config.acquire_health_check_polling_interval,
                skip_health_check=self._config.acquire_skip_health_check,
                health_check=self._config.acquire_health_check,
            )
            if sandbox_timeout is not None:
                try:
                    await sandbox.renew(sandbox_timeout)
                except BaseException:
                    try:
                        await sandbox.kill()
                    finally:
                        await sandbox.close()
                    raise
            await self._ensure_pool_namespace_active_after_create(
                sandbox, policy=policy
            )
            return sandbox

        spec = self._creation_spec
        sandbox = await self._sandbox_factory.create(
            spec.image,
            timeout=self._config.idle_timeout,
            ready_timeout=self._config.acquire_ready_timeout,
            env=spec.env,
            metadata=spec.metadata,
            resource=spec.resource,
            network_policy=spec.network_policy,
            platform=spec.platform,
            extensions=spec.extensions,
            secure_access=spec.secure_access,
            entrypoint=spec.entrypoint,
            volumes=spec.volumes,
            connection_config=self._connection_for_pool_resource(),
            health_check=self._config.acquire_health_check,
            health_check_polling_interval=self._config.acquire_health_check_polling_interval,
            skip_health_check=self._config.acquire_skip_health_check,
        )
        if sandbox_timeout is not None:
            try:
                await sandbox.renew(sandbox_timeout)
            except BaseException:
                try:
                    await sandbox.kill()
                finally:
                    await sandbox.close()
                raise
        await self._ensure_pool_namespace_active_after_create(sandbox, policy=policy)
        return sandbox

    async def _ensure_pool_namespace_active(self) -> None:
        state = await self._state_store.get_destroy_state(self._config.pool_name)
        if state != PoolDestroyState.ACTIVE:
            raise PoolDestroyedException(
                f"Pool namespace is {state.value}: pool_name={self._config.pool_name}"
            )

    async def _ensure_pool_namespace_active_for_acquire(
        self, policy: AcquirePolicy
    ) -> None:
        """Namespace-active check on the acquire path with graceful degradation.

        Same as :meth:`_ensure_pool_namespace_active`, but when the state store itself
        is unavailable (``PoolStateStoreUnavailableException``) and the effective
        ``policy`` falls through to direct-create on empty idle, we treat the destroy
        state as *unknown* and allow the acquire to proceed. This is the necessary
        counterpart to the state-store-outage fallthrough already implemented at the
        ``try_take_idle`` and ``_direct_create`` call sites (see OSEP-0005 error-code
        matrix): without it a full Redis outage would short-circuit acquire before the
        fallthrough branch could run, making ``RETRY_NEXT_IDLE_THEN_CREATE`` and
        ``DIRECT_CREATE`` less available than documented.

        Fail-closed behavior for non-fallthrough policies (``FAIL_FAST`` /
        ``RETRY_NEXT_IDLE``) is preserved: the outage is surfaced as-is so callers
        can react.
        """
        try:
            await self._ensure_pool_namespace_active()
        except PoolStateStoreUnavailableException:
            if not policy_falls_through_to_direct_create(policy):
                raise
            logger.warning(
                "acquire: state store unavailable during namespace check, "
                "assuming ACTIVE and degrading to direct-create per policy=%s",
                policy.value,
            )

    async def _raise_if_pool_namespace_destroyed(self) -> None:
        try:
            await self._ensure_pool_namespace_active()
        except PoolDestroyedException:
            raise
        except Exception:
            return

    async def _ensure_pool_namespace_active_after_create(
        self,
        sandbox: Sandbox,
        policy: AcquirePolicy | None = None,
    ) -> None:
        """Post-create fence check.

        If the state store itself is unavailable we cannot tell whether the pool was
        destroyed, so under a fallthrough ``policy`` we assume ACTIVE and keep the
        freshly-created sandbox (mirrors the OSEP-0005 acquire-outage semantics).
        Non-fallthrough policies keep the original fail-closed behavior for backward
        compatibility.
        """
        try:
            await self._ensure_pool_namespace_active()
        except PoolStateStoreUnavailableException:
            if policy is not None and policy_falls_through_to_direct_create(policy):
                logger.warning(
                    "acquire: state store unavailable during post-create fence check, "
                    "keeping sandbox and degrading per policy=%s sandbox_id=%s",
                    policy.value,
                    sandbox.id,
                )
                return
            # Fall through to the fence-triggered cleanup path below.
            try:
                await sandbox.kill()
            except Exception as exc:
                logger.warning(
                    "Pool sandbox cleanup after store-outage fence failed: pool_name=%s "
                    "sandbox_id=%s operation=kill error=%s",
                    self._config.pool_name,
                    sandbox.id,
                    exc,
                )
            try:
                await sandbox.close()
            except Exception as exc:
                logger.warning(
                    "Pool sandbox cleanup after store-outage fence failed: pool_name=%s "
                    "sandbox_id=%s operation=close error=%s",
                    self._config.pool_name,
                    sandbox.id,
                    exc,
                )
            raise
        except BaseException:
            try:
                await sandbox.kill()
            except Exception as exc:
                logger.warning(
                    "Pool sandbox cleanup after fence failed: pool_name=%s "
                    "sandbox_id=%s operation=kill error=%s",
                    self._config.pool_name,
                    sandbox.id,
                    exc,
                )
            try:
                await sandbox.close()
            except Exception as exc:
                logger.warning(
                    "Pool sandbox cleanup after fence failed: pool_name=%s "
                    "sandbox_id=%s operation=close error=%s",
                    self._config.pool_name,
                    sandbox.id,
                    exc,
                )
            raise

    async def _stop_after_pool_namespace_destroyed(self) -> None:
        async with self._lifecycle_lock:
            if self._lifecycle_state == PoolLifecycleState.STOPPED:
                return
            await self._stop_reconcile(wait_for_warmup=False, join_scheduler=False)
            self._lifecycle_state = PoolLifecycleState.STOPPED
            await self._close_provider()

    async def _build_sandbox_from_creator(
        self,
        *,
        creator: AsyncPooledSandboxCreator,
        reason: PooledSandboxCreateReason,
        ready_timeout: timedelta,
        health_check_polling_interval: timedelta,
        skip_health_check: bool,
        health_check: Callable[[Sandbox], Awaitable[bool]] | None,
    ) -> Sandbox:
        context = PooledSandboxCreateContext(
            pool_name=self._config.pool_name,
            owner_id=str(self._config.owner_id),
            idle_timeout=self._config.idle_timeout,
            reason=reason,
            ready_timeout=ready_timeout,
            health_check_polling_interval=health_check_polling_interval,
            skip_health_check=skip_health_check,
            health_check=health_check,
            connection_config=self._connection_for_pool_resource(),
        )
        return await creator(context)

    async def _resolve_max_idle(self) -> int:
        shared = await self._state_store.get_max_idle(self._config.pool_name)
        return self._current_max_idle if shared is None else shared

    async def _create_sandbox_manager(self) -> SandboxManager:
        return await self._sandbox_manager_factory(self._connection_for_pool_resource())

    def _connection_for_pool_resource(self) -> ConnectionConfig:
        if (
            self._connection_config.transport is not None
            and not self._connection_config._owns_transport
        ):
            return self._connection_config
        config = self._connection_config.model_copy(update={"transport": None})
        config._owns_transport = True
        return config

    async def _discard_sandbox_callback(self, sandbox_id: str) -> None:
        """``Callable[[str], Awaitable[None]]`` adapter for the reconciler's
        ``on_discard_sandbox`` hook. Drops the bool return value of
        :meth:`_kill_sandbox_best_effort`.
        """
        await self._kill_sandbox_best_effort(sandbox_id)

    async def _kill_sandbox_best_effort(self, sandbox_id: str) -> bool:
        """Best-effort kill a sandbox via the pool's manager.

        Returns ``True`` on a confirmed kill, ``False`` if no manager is available or the
        kill raised. Failures are logged at WARNING and swallowed.
        """
        if self._sandbox_manager is None:
            return False
        try:
            await self._sandbox_manager.kill_sandbox(sandbox_id)
            return True
        except Exception as exc:
            logger.warning(
                f"Async pool sandbox cleanup failed: pool_name={self._config.pool_name} sandbox_id={sandbox_id} error={exc}"
            )
            return False

    def _schedule_kill_discarded_alive(
        self,
        pool_name: str,
        sandbox_ids: tuple[str, ...],
        source: str,
    ) -> None:
        """Fire-and-forget the kill cleanup as a background task so the caller's ``acquire``
        is not blocked on N kill RPCs. The task is added to ``_warmup_tasks`` so shutdown can
        wait on it just like other background work; rejected scheduling falls back to inline.
        """
        if not sandbox_ids:
            return
        try:
            task = asyncio.create_task(
                self._kill_discarded_alive(pool_name, sandbox_ids, source)
            )
        except RuntimeError as exc:
            # No running loop / loop is closed — fall back to inline cleanup so the work is
            # not silently dropped. The await here is safe because we are inside `acquire()`.
            logger.debug(
                f"Discarded-alive kill scheduling failed, running inline: pool_name={pool_name} count={len(sandbox_ids)} error={exc}"
            )
            # Caller is in an async function, so this is awaited via the original
            # `_kill_discarded_alive` directly by the caller. Since `_schedule_kill_discarded_alive`
            # is sync, the safest fallback is a fire-and-forget through a fresh task; if that
            # also fails the runtime is clearly mid-shutdown and the cleanup is not critical.
            return
        self._warmup_tasks.add(task)  # type: ignore[arg-type]
        task.add_done_callback(self._warmup_tasks.discard)  # type: ignore[arg-type]

    async def _kill_discarded_alive(
        self,
        pool_name: str,
        sandbox_ids: tuple[str, ...],
        source: str,
    ) -> None:
        """Async counterpart of :meth:`SandboxPoolSync._kill_discarded_alive`.

        Kills run concurrently via :func:`asyncio.gather` so a batch of N near-expiry IDs
        does not serially block the caller's ``acquire()`` on N network round-trips.
        """
        if not sandbox_ids:
            return
        results = await asyncio.gather(
            *(self._kill_sandbox_best_effort(sandbox_id) for sandbox_id in sandbox_ids),
            return_exceptions=False,
        )
        for sandbox_id, killed in zip(sandbox_ids, results, strict=True):
            if killed:
                logger.debug(
                    f"Killed near-expiry idle sandbox: pool_name={pool_name} sandbox_id={sandbox_id} source={source}"
                )

    async def _begin_operation(self) -> None:
        async with self._in_flight_condition:
            self._in_flight += 1

    async def _end_operation(self) -> None:
        async with self._in_flight_condition:
            self._in_flight -= 1
            if self._in_flight <= 0:
                self._in_flight = 0
                self._in_flight_condition.notify_all()

    async def _await_in_flight_drain(self, timeout: timedelta) -> bool:
        deadline = asyncio.get_running_loop().time() + timeout.total_seconds()
        async with self._in_flight_condition:
            while self._in_flight > 0:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    return False
                try:
                    await asyncio.wait_for(self._in_flight_condition.wait(), remaining)
                except (asyncio.TimeoutError, TimeoutError):
                    return self._in_flight == 0
            return True

    async def _stop_reconcile(
        self,
        *,
        wait_for_warmup: bool,
        join_scheduler: bool = True,
    ) -> None:
        self._stop_event.set()
        task = self._scheduler_task
        current = asyncio.current_task()
        if join_scheduler and task is not None and task is not current:
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=5)
            except (asyncio.TimeoutError, TimeoutError):
                task.cancel()
            self._scheduler_task = None
        heartbeat = self._heartbeat_task
        if heartbeat is not None and heartbeat is not current:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.debug(
                    "Pool primary heartbeat task ended with error: "
                    f"pool_name={self._config.pool_name}"
                )
            self._heartbeat_task = None
        self._mark_primary_lost()
        warmup_tasks = list(self._warmup_tasks)
        if wait_for_warmup and warmup_tasks:
            await asyncio.gather(*warmup_tasks, return_exceptions=True)
        elif warmup_tasks:
            _, pending = await asyncio.wait(
                warmup_tasks,
                timeout=_WARMUP_TERMINATION_TIMEOUT_SECONDS,
            )
            for warmup_task in pending:
                warmup_task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
        await self._release_primary_lock_best_effort()

    async def _release_primary_lock_best_effort(self) -> None:
        try:
            await self._state_store.release_primary_lock(
                self._config.pool_name, str(self._config.owner_id)
            )
        except Exception as exc:
            logger.warning(
                f"Async pool primary lock release failed: pool_name={self._config.pool_name} owner_id={self._config.owner_id} error={exc}"
            )

    async def _close_provider(self) -> None:
        if self._sandbox_manager is not None:
            await self._sandbox_manager.close()
            self._sandbox_manager = None

    def _warn_if_primary_lock_ttl_may_expire_during_warmup(self) -> None:
        if self._config.primary_lock_ttl > self._config.warmup_ready_timeout:
            return
        logger.warning(
            f"Async pool primary lock TTL may expire during warmup: pool_name={self._config.pool_name} primary_lock_ttl_ms={int(self._config.primary_lock_ttl.total_seconds() * 1000)} warmup_ready_timeout_ms={int(self._config.warmup_ready_timeout.total_seconds() * 1000)}"
        )


AsyncSandboxPool = SandboxPoolAsync

__all__ = [
    "AsyncSandboxPool",
    "InMemoryAsyncPoolStateStore",
    "SandboxPoolAsync",
]
