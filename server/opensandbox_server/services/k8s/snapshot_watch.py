# Copyright 2026 Alibaba Group Holding Ltd.
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

"""Shared LIST/WATCH-backed change gate for snapshot runtimes.

Snapshot runtimes block their create worker until the snapshot resource
reaches a terminal phase. This module replaces sleep-polling with informer
events while keeping that blocking contract: workers sleep on a per-snapshot
event that the informer reactor sets, and fall back to bounded re-checks
whenever the watch is unavailable or an event is missed.

Events only accelerate convergence; correctness always comes from re-reading
the snapshot status after each wake, so watch breaks, reconnects, and SYNC
resyncs degrade to the fallback interval rather than to stale results.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Dict, Tuple

logger = logging.getLogger(__name__)

# Lower bound for a single wait so poll-fallback loops with a zero configured
# interval cannot spin without bound between status re-reads.
_MIN_WAIT_SECONDS = 0.05


class SnapshotChangeGate:
    """Fan out informer events to per-snapshot ``threading.Event`` waiters."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._waiters: Dict[Tuple[str, str], threading.Event] = {}

    def handle_event(self, event_type: str, obj: Dict[str, Any]) -> None:
        """Informer reactor callback for ADDED/MODIFIED/DELETED/SYNC events."""
        metadata = obj.get("metadata") if isinstance(obj, dict) else None
        name = metadata.get("name") if isinstance(metadata, dict) else None
        if not name:
            return
        namespace = metadata.get("namespace") or ""
        self.notify(namespace, name)

    def register(self, namespace: str, name: str) -> threading.Event:
        """Register a waiter; returns the event the caller should wait on."""
        event = threading.Event()
        with self._lock:
            self._waiters[(namespace, name)] = event
        return event

    def unregister(self, namespace: str, name: str, event: threading.Event) -> None:
        """Remove a waiter; a stale unregister never removes a newer waiter."""
        with self._lock:
            if self._waiters.get((namespace, name)) is event:
                del self._waiters[(namespace, name)]

    def notify(self, namespace: str, name: str) -> None:
        with self._lock:
            event = self._waiters.get((namespace, name))
        if event is not None:
            event.set()


class SnapshotChangeWatcher:
    """Wake snapshot waiters from K8sClient informer events.

    One watcher per runtime (group/version/plural); informers are started
    lazily per namespace through ``K8sClient.watch_custom_objects`` and their
    reactor events fan out through the gate. When informers are disabled or
    the watch cannot be established, waits degrade to the configured interval,
    which is also the missed-event cap while the watch is healthy.
    """

    def __init__(
        self,
        k8s_client,
        *,
        group: str,
        version: str,
        plural: str,
        wait_interval_seconds: float,
    ) -> None:
        self._k8s_client = k8s_client
        self._group = group
        self._version = version
        self._plural = plural
        self._wait_interval_seconds = max(wait_interval_seconds, _MIN_WAIT_SECONDS)
        self._gate = SnapshotChangeGate()
        self._watched_namespaces: set[str] = set()
        self._lock = threading.Lock()

    @property
    def gate(self) -> SnapshotChangeGate:
        return self._gate

    def wait_for_change(self, namespace: str, name: str, timeout_seconds: float) -> None:
        """Block until the resource changes, the interval elapses, or the timeout expires."""
        self._ensure_watch(namespace)
        event = self._gate.register(namespace, name)
        try:
            event.wait(min(max(timeout_seconds, 0.0), self._wait_interval_seconds))
        finally:
            self._gate.unregister(namespace, name, event)

    def _ensure_watch(self, namespace: str) -> None:
        with self._lock:
            if namespace in self._watched_namespaces:
                return
        watch_custom_objects = getattr(self._k8s_client, "watch_custom_objects", None)
        if watch_custom_objects is None:
            # Test doubles and legacy clients without watch support.
            return
        try:
            informer = watch_custom_objects(
                self._group, self._version, namespace, self._plural, self._gate.handle_event
            )
        except Exception as exc:  # noqa: BLE001 - the watch must never break waiting
            logger.warning(
                "Snapshot change watch for %s/%s failed to start; "
                "falling back to re-checks every %.1fs: %s",
                namespace,
                self._plural,
                self._wait_interval_seconds,
                exc,
            )
            return
        if informer is None:
            logger.debug(
                "Informers disabled; snapshot changes in %s re-checked every %.1fs",
                namespace,
                self._wait_interval_seconds,
            )
            return
        with self._lock:
            self._watched_namespaces.add(namespace)


__all__ = [
    "SnapshotChangeGate",
    "SnapshotChangeWatcher",
]
