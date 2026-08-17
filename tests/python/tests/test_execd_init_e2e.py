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
E2E tests for execd-as-init mode (OSEP-0018).

Requires a server running with ``runtime.execd_run_as_init = true`` (the
dedicated real-e2e and kubernetes-nightly jobs set it). Verifies the
container-level init contract through the SDK:

- execd is PID 1 and the workload's parent
- orphaned children are reaped (no zombie accumulation under PID 1)
- in-namespace ``kill -9 1`` is inert (kernel signal shield)
- the workload cannot read execd's environment (``/proc/1/environ`` denied by
  non-dumpable, independent of Landlock)
- ``GET /v1/isolated/capabilities`` reports ``hardening.init_mode = pid1``
"""

import logging
import time
from datetime import timedelta

import pytest
from opensandbox import SandboxSync
from opensandbox.models.execd import RunCommandOpts
from opensandbox.models.sandboxes import SandboxImageSpec

from tests.base_e2e_test import (
    create_connection_config_sync,
    get_e2e_sandbox_resource,
    get_sandbox_image,
)

logger = logging.getLogger(__name__)

EXECD_CAPABILITIES_URL = "http://127.0.0.1:44772/v1/isolated/capabilities"


def _run_command(sandbox, command: str) -> str:
    """Run a command and return its combined stdout."""
    result = sandbox.commands.run(command, opts=RunCommandOpts())
    assert result.error is None, f"command failed: {result.error}"
    return "".join(msg.text for msg in result.logs.stdout)


class TestExecdInitE2E:
    @pytest.fixture(scope="module", autouse=True)
    def sandbox(self):
        connection_config = create_connection_config_sync()
        sbx = SandboxSync.create(
            image=SandboxImageSpec(get_sandbox_image()),
            resource=get_e2e_sandbox_resource(),
            connection_config=connection_config,
            timeout=timedelta(minutes=5),
            ready_timeout=timedelta(seconds=60),
            metadata={"tag": "execd-init-e2e"},
        )
        logger.info("✓ execd-init sandbox created: %s", sbx.id)
        yield sbx
        try:
            sbx.close()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Teardown: sandbox.close() failed: %s", exc, exc_info=True)

    def test_pid1_is_execd(self, sandbox) -> None:
        assert _run_command(sandbox, "cat /proc/1/comm").strip() == "execd"

    def test_workload_is_direct_child_of_execd(self, sandbox) -> None:
        # /proc/$$/stat field 4 is the parent pid; the run-command shell is
        # a direct child of execd (PID 1).
        ppid = _run_command(sandbox, "awk '{print $4}' /proc/$$/stat").strip()
        assert ppid == "1", f"workload ppid = {ppid}, want 1"

    def test_orphans_are_reaped(self, sandbox) -> None:
        # Background children reparent to PID 1 and must be reaped by execd.
        _run_command(sandbox, "for i in $(seq 1 5); do ( sleep 0.1 ) & done")
        time.sleep(2)
        zombies = _run_command(
            sandbox,
            "z=0; for p in /proc/[0-9]*; do "
            "stat=$(cat \"$p/stat\" 2>/dev/null) || continue; "
            "stat=${stat#*)}; set -- $stat; "
            "[ \"$1\" = Z ] && [ \"$2\" = 1 ] && z=$((z+1)); done; echo $z",
        ).strip()
        assert zombies == "0", f"zombies under pid 1: {zombies}"

    def test_kill9_pid1_is_inert(self, sandbox) -> None:
        assert "alive" in _run_command(sandbox, "kill -9 1; echo alive")

    def test_workload_cannot_read_execd_environ(self, sandbox) -> None:
        result = sandbox.commands.run("cat /proc/1/environ", opts=RunCommandOpts())
        assert result.error is not None, "reading execd's /proc/1/environ must be denied"
        stderr = "".join(msg.text for msg in result.logs.stderr)
        assert "Permission denied" in stderr or "Operation not permitted" in stderr

    def test_hardening_reports_pid1(self, sandbox) -> None:
        probe = (
            "python3 -c \"import json,urllib.request;"
            f"print(json.load(urllib.request.urlopen('{EXECD_CAPABILITIES_URL}'))"
            "['hardening']['init_mode'])\""
        )
        init_mode = _run_command(sandbox, probe).strip()
        assert init_mode == "pid1", f"hardening.init_mode = {init_mode}, want pid1"
