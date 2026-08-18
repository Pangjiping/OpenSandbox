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
E2E tests for the server-path hardening floor (OSEP-0018 R-i).

Requires a docker-bridge server running with ``runtime.execd_run_as_init =
true`` and the following server config (see
scripts/python-execd-hardening-e2e.sh):

    [docker]
    sandbox_env = { EXECD_ISOLATION_CONFIG = "/etc/opensandbox/isolation.toml" }
    sandbox_binds = [
        "/tmp/opensandbox-e2e/workspace:/workspace",
        "/tmp/opensandbox-e2e/isolation.hardened.toml:/etc/opensandbox/isolation.toml",
    ]

Verifies through the SDK, with the whole server -> sandbox -> execd path
running with ``[hardening]``/``[landlock]`` enabled:

- every execd-spawned path (entrypoint + /command) runs reduced:
  no effective caps, bounding set trimmed, seccomp filter mode, no_new_privs
- execd's config env is stripped from the workload (EXECD_ISOLATION_CONFIG
  and EXECD_ACCESS_TOKEN absent from /command; EXECD_ACCESS_TOKEN absent
  from the entrypoint)
- Landlock confinement: /tmp writable, /etc/passwd not writable, the
  bind-mounted workspace writable AND executable (exercises the launcher's
  mount expansion), /proc/1/environ denied
- GET /v1/isolated/capabilities reports init_mode=pid1 with
  cap_drop/seccomp active and landlock active|unsupported

A second class covers the fail-open degradation with CAP_SETPCAP dropped
from the container ceiling (run by the script's phase 2, gated on
OPENSANDBOX_HARDENING_DEGRADATION=true):

- cap_drop reports degraded with a concrete reason; seccomp/landlock stay
  active
- the floor still applies (CapEff=0, seccomp, NNP) but the bounding set is
  NOT trimmed (fail-open: workloads keep the container ceiling's bounding
  set)
"""

import json
import logging
import os
import time

import pytest
from opensandbox import SandboxSync

from tests.test_execd_init_e2e import (
    EXECD_CAPABILITIES_URL,
    _create_sandbox,
    _destroy,
    _run_command,
)

logger = logging.getLogger(__name__)

WORKSPACE_HOST = os.environ.get(
    "OPENSANDBOX_HARDENING_WORKSPACE_HOST", "/tmp/opensandbox-e2e/workspace"
)

# The entrypoint is launched with bootstrapEnv: EXECD_ACCESS_TOKEN is
# stripped, everything else (incl. EXECD_ISOLATION_CONFIG) is kept for
# image entrypoint scripts. /command uses the full config blacklist.
ENTRYPOINT_BOOTSTRAP_ENV_STRIPPED = ["EXECD_ACCESS_TOKEN"]
COMMAND_ENV_STRIPPED = [
    "EXECD_ACCESS_TOKEN",
    "EXECD_ISOLATION_CONFIG",
    "JUPYTER_HOST",
    "JUPYTER_TOKEN",
    "EXECD_ENVS",
]

_HARDENING_REPORT: dict | None = None


def _hardening_report(sandbox: SandboxSync) -> dict:
    """Probe execd's capabilities endpoint once (per process) and cache."""
    global _HARDENING_REPORT
    if _HARDENING_REPORT is None:
        probe = (
            "python3 -c \"import json,urllib.request;"
            f"print(json.dumps(json.load(urllib.request.urlopen('{EXECD_CAPABILITIES_URL}'))['hardening']))\""
        )
        _HARDENING_REPORT = json.loads(_run_command(sandbox, probe))
    return _HARDENING_REPORT


def _landlock_state(sandbox: SandboxSync) -> str:
    return _hardening_report(sandbox)["landlock"]["state"]


def _status_fields(sandbox: SandboxSync, fields: list[str]) -> dict:
    """Parse selected /proc/self/status fields of the /command shell.

    Two constraints: (1) the read happens with the shell's own read loop,
    NOT with forked helpers — under Landlock the ruleset only grants the
    launcher's own /proc/<pid> (documented OSEP-0018 limitation), so a
    forked grep/cat would get EACCES on its own /proc/self; (2) execd's
    /command SSE output strips newlines, so the values must come out as a
    single line (space-separated key=value pairs).
    """
    arms = "\n".join(
        f'      {name}:*) {name}="${{line#*:\t}}" ;;' for name in fields
    )
    echo = " ".join(f'"{n}=${n}"' for n in fields)
    script = (
        'while IFS= read -r line; do\n'
        '  case "$line" in\n'
        f"{arms}\n"
        '  esac\n'
        'done < /proc/self/status\n'
        f'echo {echo}'
    )
    out = _run_command(sandbox, script)
    parsed: dict[str, str] = {}
    for token in out.split():
        key, _, value = token.partition("=")
        parsed[key.strip()] = value.strip()
    return parsed


def _wait_for_host_file(path: str, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return
        time.sleep(1)
    pytest.fail(f"host-side file {path} never appeared")


def _parse_entrypoint_dump(sbx: SandboxSync) -> tuple[dict, dict]:
    """Read the entrypoint's /proc/self/status + env dump (written to the
    bind-mounted workspace) and split it into status fields and an env dict."""
    path = os.path.join(WORKSPACE_HOST, f"state-{sbx.id}.txt")
    _wait_for_host_file(path)
    with open(path, encoding="utf-8") as f:
        content = f.read()
    status_part, _, env_part = content.partition("=== env ===")
    status: dict[str, str] = {}
    for line in status_part.splitlines():
        key, _, value = line.partition(":")
        status[key.strip()] = value.strip()
    env = dict(line.split("=", 1) for line in env_part.splitlines() if "=" in line)
    return status, env


class TestHardeningE2E:
    @pytest.fixture(scope="module", autouse=True)
    def sandbox(self):
        # Entrypoint: dump its own /proc/self/status + env to the
        # bind-mounted workspace (host-readable), then stay alive. The dump
        # is written once at startup, before any /command churn, so it
        # reflects exactly the launcher-applied floor. The status is read
        # with the shell's own loop, NOT `cat`: under Landlock a forked
        # descendant resolves its own /proc/<pid>, which the inherited
        # ruleset does not grant (documented OSEP-0018 limitation), so a
        # forked helper would get EACCES.
        sbx = _create_sandbox(
            entrypoint=[
                "sh",
                "-c",
                "out=/workspace/state-$OPENSANDBOX_ID.txt; "
                "{ echo '=== status ==='; "
                "while IFS= read -r line; do echo \"$line\"; done < /proc/self/status; "
                "echo '=== env ==='; env | sort; } > \"$out\" 2>&1; "
                "while :; do sleep 1; done",
            ],
            tag="execd-hardening-e2e",
        )
        logger.info("✓ hardening sandbox created: %s", sbx.id)
        yield sbx
        _destroy(sbx)

    def test_capabilities_endpoint_reports_hardening(self, sandbox) -> None:
        report = _hardening_report(sandbox)
        assert report["init_mode"] == "pid1", f"init_mode = {report['init_mode']}"
        assert report["signal_shield"] is True
        assert report["cap_drop"]["state"] == "active", report["cap_drop"]
        assert report["seccomp"]["state"] == "active", report["seccomp"]
        assert report["landlock"]["state"] in ("active", "unsupported"), (
            report["landlock"]
        )
        assert report["ebpf"]["state"] == "disabled", report["ebpf"]

    def test_command_path_is_reduced(self, sandbox) -> None:
        # /command children go through the same launcher prelude as the
        # entrypoint: zero effective caps, bounding set trimmed, seccomp
        # filter mode, no_new_privs.
        status = _status_fields(sandbox, ["CapEff", "CapBnd", "Seccomp", "NoNewPrivs"])
        assert status["CapEff"] == "0000000000000000", status
        assert status["CapBnd"] == "0000000000000000", status
        assert status["Seccomp"] == "2", status
        assert status["NoNewPrivs"] == "1", status

    def test_command_path_strips_execd_config_env(self, sandbox) -> None:
        env = _run_command(sandbox, "env")
        for name in COMMAND_ENV_STRIPPED:
            assert f"{name}=" not in env, f"/command env leaked {name}"

    def test_entrypoint_is_reduced_and_env_stripped(self, sandbox) -> None:
        status, env = _parse_entrypoint_dump(sandbox)
        assert status["CapEff"] == "0000000000000000", status
        assert status["CapBnd"] == "0000000000000000", status
        assert status["Seccomp"] == "2", status
        assert status["NoNewPrivs"] == "1", status
        for name in ENTRYPOINT_BOOTSTRAP_ENV_STRIPPED:
            assert name not in env, f"entrypoint env leaked {name}"

    def test_workload_cannot_read_execd_environ(self, sandbox) -> None:
        # PR_SET_DUMPABLE shield: same-uid workload without CAP_SYS_PTRACE
        # cannot read execd's environment even before Landlock.
        result = sandbox.commands.run("cat /proc/1/environ")
        assert result.error is not None, "reading execd's /proc/1/environ must be denied"
        stderr = "".join(msg.text for msg in result.logs.stderr)
        assert "Permission denied" in stderr or "Operation not permitted" in stderr

    def test_tmp_is_writable(self, sandbox) -> None:
        if _landlock_state(sandbox) != "active":
            pytest.skip("landlock not active on this kernel")
        _run_command(sandbox, "echo ok > /tmp/hardening-e2e-write && rm /tmp/hardening-e2e-write")

    def test_etc_passwd_is_not_writable(self, sandbox) -> None:
        if _landlock_state(sandbox) != "active":
            pytest.skip("landlock not active on this kernel")
        result = sandbox.commands.run("echo x >> /etc/passwd")
        assert result.error is not None, "writing /etc/passwd must be denied by landlock"

    def test_workspace_bind_mount_writable_and_executable(self, sandbox) -> None:
        # The workspace is a bind mount (separate mount from /): executing a
        # script from it exercises the launcher's mount expansion (the /
        # execute grant must be merged onto the mount point), and writing to
        # it exercises the /workspace read/write rule.
        if _landlock_state(sandbox) != "active":
            pytest.skip("landlock not active on this kernel")
        _run_command(
            sandbox,
            "printf '#!/bin/sh\\necho workspace-exec-ok\\n' > /workspace/hardening-e2e.sh"
            " && chmod +x /workspace/hardening-e2e.sh && /workspace/hardening-e2e.sh",
        )


@pytest.mark.skipif(
    os.environ.get("OPENSANDBOX_HARDENING_DEGRADATION") != "true",
    reason="requires the degradation server (CAP_SETPCAP dropped); run via "
    "scripts/python-execd-hardening-e2e.sh phase 2",
)
class TestHardeningDegradationE2E:
    @pytest.fixture(scope="module", autouse=True)
    def sandbox(self):
        sbx = _create_sandbox(tag="execd-hardening-degradation-e2e")
        logger.info("✓ degradation sandbox created: %s", sbx.id)
        yield sbx
        _destroy(sbx)

    def test_cap_drop_reports_degraded_with_reason(self, sandbox) -> None:
        report = _hardening_report(sandbox)
        assert report["init_mode"] == "pid1", f"init_mode = {report['init_mode']}"
        cap_drop = report["cap_drop"]
        assert cap_drop["state"] == "degraded", cap_drop
        assert "SETPCAP" in cap_drop["message"], cap_drop
        # The remaining layers must not cascade: fail-open is per layer.
        assert report["seccomp"]["state"] == "active", report["seccomp"]
        assert report["landlock"]["state"] in ("active", "unsupported"), (
            report["landlock"]
        )

    def test_floor_still_applies_without_setpcap(self, sandbox) -> None:
        # Bounding-set trim is skipped without CAP_SETPCAP, but capset (drop
        # own caps), seccomp and NNP still apply — the workload is reduced
        # even in the degraded state.
        status = _status_fields(sandbox, ["CapEff", "CapBnd", "Seccomp", "NoNewPrivs"])
        assert status["CapEff"] == "0000000000000000", status
        assert status["Seccomp"] == "2", status
        assert status["NoNewPrivs"] == "1", status
        # Fail-open: the bounding set keeps the container ceiling caps.
        assert status["CapBnd"] != "0000000000000000", status
