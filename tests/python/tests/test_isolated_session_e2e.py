#
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
#
"""
E2E tests for isolated session (OSEP-0013 bwrap namespace isolation).
"""

import logging

import pytest
from opensandbox import Sandbox
from opensandbox.models.execd import ExecutionHandlers, OutputMessage
from opensandbox.models.isolated import (
    CreateIsolatedSessionRequest,
    IsolatedRunOpts,
    IsolatedWorkspaceSpec,
)

from tests.base_e2e_test import (
    create_connection_config,
    get_e2e_sandbox_resource,
    get_sandbox_image,
)

logger = logging.getLogger(__name__)


@pytest.mark.asyncio
class TestIsolatedSessionE2E:
    """E2E tests for /v1/isolated/* via Python SDK."""

    sandbox: Sandbox | None = None

    @pytest.fixture(scope="class", autouse=True)
    async def _sandbox_lifecycle(self, request):
        cls = request.cls
        config = create_connection_config()
        sandbox = await Sandbox.create(
            get_sandbox_image(),
            connection_config=config,
            resource=get_e2e_sandbox_resource(),
            extensions={"bootstrap.execd.isolation": "enable"},
        )
        cls.sandbox = sandbox

        caps = await sandbox.isolation.capabilities()
        logger.info(
            "Isolation capabilities: available=%s isolator=%s version=%s "
            "commit_supported=%s diff_supported=%s message=%s",
            caps.available, caps.isolator, caps.version,
            caps.commit_supported, caps.diff_supported, caps.message,
        )
        if not caps.available:
            pytest.fail(f"Isolation NOT available: {caps.message or 'unknown reason'}")

        yield

        await sandbox.kill()
        await sandbox.close()

    async def test_capabilities(self):
        caps = await self.sandbox.isolation.capabilities()
        assert isinstance(caps.available, bool)

    async def test_session_lifecycle(self):
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        assert session.session_id
        assert session.info.created_at is not None

        state = await session.get()
        assert state.status == "active"

        await session.delete()

    async def test_run_echo(self):
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            result = await session.run("echo hello-isolation")
            assert "hello-isolation" in result.text
        finally:
            await session.delete()

    async def test_pid_isolation(self):
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            result = await session.run("echo $$")
            pid = int(result.text.strip())
            assert pid <= 2, f"expected PID 1 or 2 in namespace, got {pid}"
        finally:
            await session.delete()

    async def test_run_with_envs(self):
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            result = await session.run(
                "echo $MY_VAR",
                opts=IsolatedRunOpts(envs={"MY_VAR": "test-value-42"}),
            )
            assert "test-value-42" in result.text
        finally:
            await session.delete()

    async def test_session_state_persists(self):
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            await session.run("export PERSIST_VAR=abc123")
            result = await session.run("echo $PERSIST_VAR")
            assert "abc123" in result.text
        finally:
            await session.delete()

    async def test_tmp_isolation(self):
        await self.sandbox.commands.run("mkdir -p /workspace")
        session_a = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/workspace", mode="rw"),
                profile="strict",
            )
        )
        session_b = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/workspace", mode="rw"),
                profile="strict",
            )
        )
        try:
            await session_a.run("echo secret > /tmp/isolated_test_file.txt")
            result = await session_b.run(
                "cat /tmp/isolated_test_file.txt 2>&1 || echo NOT_FOUND"
            )
            assert "NOT_FOUND" in result.text or "No such file" in result.text
        finally:
            await session_a.delete()
            await session_b.delete()

    async def test_run_with_handlers(self):
        collected: list[str] = []

        async def on_stdout(msg: OutputMessage):
            collected.append(msg.text)

        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            await session.run(
                "echo handler-test",
                handlers=ExecutionHandlers(on_stdout=on_stdout),
            )
            combined = "".join(collected)
            assert "handler-test" in combined
        finally:
            await session.delete()

    async def test_overlay_mode(self):
        marker = "overlay_marker_file.txt"
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="overlay"),
            )
        )
        try:
            await session.run(f"echo overlay-data > /tmp/{marker}")
            host_check = await self.sandbox.commands.run(
                f"cat /tmp/{marker} 2>&1 || echo NOT_FOUND"
            )
            assert "NOT_FOUND" in host_check.text or "No such file" in host_check.text
        finally:
            await session.delete()

    async def test_files_write_via_run_and_read_via_run(self):
        """Verify file operations work through run() commands."""
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            await session.run("echo 'hello from sdk' > /tmp/hello.txt")
            result = await session.run("cat /tmp/hello.txt")
            assert "hello from sdk" in result.text
        finally:
            await session.delete()

    async def test_files_persistence_across_runs(self):
        """Files written in one run are visible in the next."""
        session = await self.sandbox.isolation.create(
            CreateIsolatedSessionRequest(
                workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
            )
        )
        try:
            await session.run("echo run1-data > /tmp/persist.txt")
            await session.run("mkdir -p /tmp/subdir && echo nested > /tmp/subdir/file.txt")
            result = await session.run("cat /tmp/persist.txt && cat /tmp/subdir/file.txt")
            assert "run1-data" in result.text
            assert "nested" in result.text
        finally:
            await session.delete()

    async def test_delete_nonexistent_session(self):
        from opensandbox.exceptions import SandboxApiException
        with pytest.raises(SandboxApiException):
            # Create a fake session handle by going through the service
            # The delete on a nonexistent ID should raise
            fake_session = await self.sandbox.isolation.create(
                CreateIsolatedSessionRequest(
                    workspace=IsolatedWorkspaceSpec(path="/tmp", mode="rw"),
                )
            )
            await fake_session.delete()
            await fake_session.delete()  # second delete should fail
