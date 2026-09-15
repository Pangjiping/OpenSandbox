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

from __future__ import annotations

import threading
import time
from typing import Any

from opensandbox_server.services.k8s.snapshot_watch import (
    SnapshotChangeGate,
    SnapshotChangeWatcher,
)


def _cr_event(name: str, namespace: str = "default") -> dict:
    return {"metadata": {"name": name, "namespace": namespace}}


class RecordingWatchClient:
    """K8sClient double capturing watch_custom_objects calls."""

    def __init__(self, *, raise_on_watch: bool = False, return_none: bool = False):
        self.calls: list[tuple[str, str, str, str]] = []
        self.handlers: list = []
        self._raise_on_watch = raise_on_watch
        self._return_none = return_none

    def watch_custom_objects(self, group, version, namespace, plural, event_handler):
        if self._raise_on_watch:
            raise RuntimeError("watch setup failed")
        self.calls.append((group, version, namespace, plural))
        self.handlers.append(event_handler)
        if self._return_none:
            return None
        return object()


class TestSnapshotChangeGate:
    def test_notify_wakes_registered_waiter(self) -> None:
        gate = SnapshotChangeGate()
        event = gate.register("default", "snap-1")

        gate.handle_event("MODIFIED", _cr_event("snap-1"))

        assert event.wait(timeout=1)

    def test_event_for_other_name_does_not_wake(self) -> None:
        gate = SnapshotChangeGate()
        event = gate.register("default", "snap-1")

        gate.handle_event("MODIFIED", _cr_event("snap-2"))

        assert not event.wait(timeout=0.05)

    def test_handle_event_ignores_objects_without_name(self) -> None:
        gate = SnapshotChangeGate()
        event = gate.register("default", "snap-1")

        malformed: list[Any] = [{"metadata": {}}, "not-a-dict", None]
        for payload in malformed:
            gate.handle_event("MODIFIED", payload)

        assert not event.wait(timeout=0.05)

    def test_unregister_stops_delivery(self) -> None:
        gate = SnapshotChangeGate()
        event = gate.register("default", "snap-1")
        gate.unregister("default", "snap-1", event)

        gate.handle_event("SYNC", _cr_event("snap-1"))

        assert not event.wait(timeout=0.05)

    def test_stale_unregister_keeps_newer_waiter(self) -> None:
        gate = SnapshotChangeGate()
        first = gate.register("default", "snap-1")
        second = gate.register("default", "snap-1")

        gate.unregister("default", "snap-1", first)
        gate.handle_event("MODIFIED", _cr_event("snap-1"))

        assert second.wait(timeout=1)
        assert not first.is_set()

    def test_missing_namespace_defaults_to_empty_key(self) -> None:
        gate = SnapshotChangeGate()
        event = gate.register("", "snap-1")

        gate.handle_event("SYNC", {"metadata": {"name": "snap-1"}})

        assert event.wait(timeout=1)


class TestSnapshotChangeWatcher:
    def test_wait_returns_when_event_fires_from_another_thread(self) -> None:
        client = RecordingWatchClient()
        watcher = SnapshotChangeWatcher(
            client,
            group="sandbox.opensandbox.io",
            version="v1alpha1",
            plural="sandboxsnapshots",
            wait_interval_seconds=30,
        )
        started = threading.Event()
        release = threading.Event()

        def waiter() -> None:
            started.set()
            watcher.wait_for_change("default", "snap-1", 5)
            release.set()

        thread = threading.Thread(target=waiter)
        thread.start()
        assert started.wait(timeout=1)
        assert client.handlers, "watch handler should be registered before waiting"
        client.handlers[0]("MODIFIED", _cr_event("snap-1"))

        assert release.wait(timeout=1)
        thread.join(timeout=1)

    def test_wait_falls_back_to_interval_when_no_event(self) -> None:
        client = RecordingWatchClient()
        watcher = SnapshotChangeWatcher(
            client,
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=0.1,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 5)
        elapsed = time.monotonic() - started

        assert 0.05 <= elapsed < 5

    def test_wait_respects_timeout_below_interval(self) -> None:
        client = RecordingWatchClient()
        watcher = SnapshotChangeWatcher(
            client,
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=30,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 0.1)
        elapsed = time.monotonic() - started

        assert elapsed < 1

    def test_watch_registered_once_per_namespace(self) -> None:
        client = RecordingWatchClient()
        watcher = SnapshotChangeWatcher(
            client,
            group="sandbox.opensandbox.io",
            version="v1alpha1",
            plural="sandboxsnapshots",
            wait_interval_seconds=0.05,
        )

        watcher.wait_for_change("default", "snap-1", 0)
        watcher.wait_for_change("default", "snap-2", 0)
        watcher.wait_for_change("other", "snap-1", 0)

        assert client.calls == [
            ("sandbox.opensandbox.io", "v1alpha1", "default", "sandboxsnapshots"),
            ("sandbox.opensandbox.io", "v1alpha1", "other", "sandboxsnapshots"),
        ]

    def test_watch_setup_failure_keeps_interval_fallback(self) -> None:
        client = RecordingWatchClient(raise_on_watch=True)
        watcher = SnapshotChangeWatcher(
            client,
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=0.1,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 5)
        elapsed = time.monotonic() - started

        assert elapsed < 1

    def test_disabled_informers_still_wait_via_interval(self) -> None:
        client = RecordingWatchClient(return_none=True)
        watcher = SnapshotChangeWatcher(
            client,
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=0.1,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 5)

        assert 0.05 <= time.monotonic() - started < 1

    def test_client_without_watch_support_falls_back(self) -> None:
        watcher = SnapshotChangeWatcher(
            object(),
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=0.1,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 5)

        assert 0.05 <= time.monotonic() - started < 1

    def test_zero_interval_is_clamped_to_minimum(self) -> None:
        client = RecordingWatchClient()
        watcher = SnapshotChangeWatcher(
            client,
            group="g",
            version="v",
            plural="snapshots",
            wait_interval_seconds=0,
        )

        started = time.monotonic()
        watcher.wait_for_change("default", "snap-1", 5)
        elapsed = time.monotonic() - started

        assert elapsed >= 0.05
