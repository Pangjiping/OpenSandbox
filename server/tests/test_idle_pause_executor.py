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

"""FastPathPauseExecutor tests: request shape and error mapping."""

from datetime import datetime, timedelta, timezone

import pytest

from opensandbox_server.integrations.idle_pause.executor import (
    FastPathPauseExecutor,
    PauseOutcome,
)
from opensandbox_server.integrations.idle_pause.inventory import SandboxCandidate
from opensandbox_server.integrations.idle_pause.policy import validate_idle_policy
from opensandbox_server.services.fast_sandbox.fastpath_client import (
    FastPathConflict,
    FastPathError,
    FastPathFailedPrecondition,
    FastPathNotFound,
    FastPathUnavailable,
)


def _candidate() -> SandboxCandidate:
    return SandboxCandidate(
        sandbox_id="fsb_x",
        namespace="ns1",
        uid="uid-1",
        generation=7,
        state="Running",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        policy=validate_idle_policy(idle_timeout_seconds=300, on_idle="pause"),
    )


class StubFastPathClient:
    """Records pause_sandbox kwargs; raises the configured exception."""

    def __init__(self, exc: Exception | None = None):
        self.exc = exc
        self.calls: list[dict] = []

    def pause_sandbox(
        self,
        namespace: str,
        sandbox_name: str,
        *,
        expected_uid: str = "",
        expected_generation: int = 0,
        request_id: str = "",
    ) -> None:
        self.calls.append(
            {
                "namespace": namespace,
                "sandbox_name": sandbox_name,
                "expected_uid": expected_uid,
                "expected_generation": expected_generation,
                "request_id": request_id,
            }
        )
        if self.exc is not None:
            raise self.exc


def _execute(client: StubFastPathClient) -> PauseOutcome:
    return FastPathPauseExecutor(client).pause(_candidate())  # type: ignore[arg-type]


def test_pause_sends_idempotent_request_id_and_fences():
    client = StubFastPathClient()
    assert _execute(client) is PauseOutcome.ACCEPTED
    assert client.calls == [
        {
            "namespace": "ns1",
            "sandbox_name": "fsb_x",
            "expected_uid": "uid-1",
            "expected_generation": 7,
            "request_id": "idlepause-fsb_x",
        }
    ]


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (FastPathFailedPrecondition("FAILED_PRECONDITION", "state changed"), PauseOutcome.STATE_CHANGED),
        (FastPathConflict("ABORTED", "request replayed"), PauseOutcome.STATE_CHANGED),
        (FastPathNotFound("NOT_FOUND", "gone"), PauseOutcome.NOT_FOUND),
        (FastPathUnavailable("UNAVAILABLE", "down"), PauseOutcome.UNAVAILABLE),
        (FastPathError("INTERNAL", "boom"), PauseOutcome.FAILED),
    ],
)
def test_error_mapping(exc, expected):
    assert _execute(StubFastPathClient(exc=exc)) is expected
