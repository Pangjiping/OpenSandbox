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
#
"""Behavioral tests for the MCP server tool surface.

Regression coverage for the audit finding that per-call ``manager.close()`` /
``sandbox.close()`` tore down the server-wide shared HTTP transport while other
registered sandboxes still used it. Consumers now receive a non-owning clone of
the shared config.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
from opensandbox.config import ConnectionConfig

from opensandbox_mcp.server import ServerState, register_tools


class _FakeMCP:
    """Captures tools registered via the ``@tool()`` decorator."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(func):
            self.tools[func.__name__] = func
            return func

        return decorator


class _FakeManager:
    instances: list[_FakeManager] = []

    def __init__(self, config) -> None:
        self.config = config
        self.closed = False
        self.killed: list[str] = []
        _FakeManager.instances.append(self)

    @classmethod
    async def create(cls, connection_config=None):
        return cls(connection_config)

    async def kill_sandbox(self, sandbox_id: str) -> None:
        self.killed.append(sandbox_id)

    async def list_sandbox_infos(self, filter=None):
        return None

    async def close(self) -> None:
        self.closed = True


class _SpyTransport(httpx.AsyncBaseTransport):
    """Wraps a transport and records whether aclose() was invoked."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.closed = False

    async def handle_async_request(self, request):
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        self.closed = True


class _FakeSandbox:
    def __init__(self, sandbox_id: str) -> None:
        self.id = sandbox_id
        self.closed = False
        self.killed = False

    async def kill(self) -> None:
        self.killed = True

    async def close(self) -> None:
        self.closed = True


@pytest.fixture()
def server(monkeypatch):
    monkeypatch.setattr("opensandbox_mcp.server.SandboxManager", _FakeManager)
    _FakeManager.instances = []
    fake = _FakeMCP()
    state = register_tools(
        fake, connection_config=ConnectionConfig().with_transport_if_missing()
    )
    return fake, state


@pytest.mark.asyncio
async def test_kill_manager_fallback_keeps_shared_transport_open(server) -> None:
    """The manager fallback path must not close the server-wide transport."""
    fake, state = server

    spy = _SpyTransport(state.connection_config.transport)
    state.connection_config.transport = spy

    kill = fake.tools["sandbox_kill"]
    response = await kill("sbx-unknown")

    assert response.status == "killed"
    manager = _FakeManager.instances[-1]
    assert manager.killed == ["sbx-unknown"]
    assert manager.closed, "manager.close() must still release the manager itself"
    # Regression: the shared transport was closed here before the fix.
    assert spy.closed is False


@pytest.mark.asyncio
async def test_kill_registry_path_keeps_shared_transport_open(server) -> None:
    """Killing a registered sandbox must not close the shared transport."""
    fake, state = server
    fake_sandbox = _FakeSandbox("sbx-registered")
    state.sandboxes[fake_sandbox.id] = fake_sandbox  # type: ignore[assignment]

    spy = _SpyTransport(state.connection_config.transport)
    state.connection_config.transport = spy

    kill = fake.tools["sandbox_kill"]
    response = await kill(fake_sandbox.id)

    assert response.status == "killed"
    assert fake_sandbox.killed
    assert fake_sandbox.closed
    assert spy.closed is False
    assert fake_sandbox.id not in state.sandboxes


@pytest.mark.asyncio
async def test_manager_consumers_receive_non_owning_config(server) -> None:
    """Every manager/sandbox consumer gets a clone without transport ownership."""
    fake, state = server

    await fake.tools["sandbox_list"](None)  # type: ignore[operator]
    manager = _FakeManager.instances[-1]
    assert manager.config is not state.connection_config
    assert manager.config._owns_transport is False
    assert state.connection_config._owns_transport is True


@pytest.mark.asyncio
async def test_registered_sandbox_is_shared_not_reconnected(server) -> None:
    """The registry lock serializes get->connect so no duplicate Sandbox exists."""
    fake, state = server

    class _MetricsSandbox(_FakeSandbox):
        async def get_metrics(self):
            return "metrics"

    state.sandboxes["sbx-metrics"] = _MetricsSandbox("sbx-metrics")  # type: ignore[assignment]

    metrics = await fake.tools["sandbox_get_metrics"](  # type: ignore[operator]
        "sbx-metrics", connect_if_missing=True
    )
    assert metrics == "metrics"
    # Exactly the registered instance was used.
    assert isinstance(state.sandboxes["sbx-metrics"], _MetricsSandbox)


def test_borrowed_config_shares_transport_without_ownership() -> None:
    from opensandbox_mcp.server import _borrowed_config

    state = ServerState(
        connection_config=ConnectionConfig().with_transport_if_missing()
    )
    borrowed = _borrowed_config(state)

    assert borrowed is not state.connection_config
    assert borrowed.transport is state.connection_config.transport
    assert borrowed._owns_transport is False
    assert state.connection_config._owns_transport is True


@pytest.mark.asyncio
async def test_concurrent_connect_creates_single_registry_entry(
    server, monkeypatch
) -> None:
    """Two concurrent tool calls for one sandbox must not both run connect."""
    fake, state = server
    connect_calls: list[str] = []

    class _FakeServerSandbox(_FakeSandbox):
        def __init__(self, sandbox_id: str) -> None:
            super().__init__(sandbox_id)
            await_none = None  # noqa: F841

        async def get_metrics(self):
            return "metrics"

    class _FakeServerSandboxModule:
        @staticmethod
        async def connect(sandbox_id, connection_config=None, **kwargs):
            connect_calls.append(sandbox_id)
            await asyncio.sleep(0.01)
            return _MetricsSandbox(sandbox_id)

    class _MetricsSandbox(_FakeSandbox):
        async def get_metrics(self):
            return "metrics"

    monkeypatch.setattr("opensandbox_mcp.server.Sandbox", _FakeServerSandboxModule)

    await asyncio.gather(
        fake.tools["sandbox_get_metrics"]("sbx-race", connect_if_missing=True),  # type: ignore[operator]
        fake.tools["sandbox_get_metrics"]("sbx-race", connect_if_missing=True),  # type: ignore[operator]
    )

    assert connect_calls == ["sbx-race"], (
        "concurrent calls raced past the registry and connected twice"
    )
    assert state.sandboxes["sbx-race"].id == "sbx-race"
