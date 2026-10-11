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

"""Pause executor: the sweeper's single authority for issuing pauses.

``FastPathPauseExecutor`` wraps the existing ``FastPathClient.pause_sandbox``
with the OSEP-0024 pause contract: an idempotent ``idlepause-{sandbox_id}``
request id (FastPath deduplicates replays of the same idle episode) plus the
observed uid/generation fence, so a state change under the sweeper comes back
as ``FailedPrecondition`` and is simply re-evaluated on the next sweep.
"""

from __future__ import annotations

import enum
import logging
from typing import Protocol

from opensandbox_server.integrations.idle_pause.constants import IDLE_PAUSE_REQUEST_ID_PREFIX
from opensandbox_server.integrations.idle_pause.inventory import SandboxCandidate
from opensandbox_server.services.fast_sandbox.fastpath_client import (
    FastPathClient,
    FastPathConflict,
    FastPathError,
    FastPathFailedPrecondition,
    FastPathNotFound,
    FastPathUnavailable,
)

logger = logging.getLogger(__name__)


class PauseOutcome(enum.Enum):
    ACCEPTED = "accepted"  # pause intent persisted; Pausing -> Paused converges
    STATE_CHANGED = "state_changed"  # fence rejected: drop, next sweep re-evaluates
    NOT_FOUND = "not_found"  # sandbox disappeared mid-sweep
    UNAVAILABLE = "unavailable"  # FastPath unreachable: leave the sandbox Running
    FAILED = "failed"  # any other FastPath error


class PauseExecutor(Protocol):
    def pause(self, candidate: SandboxCandidate) -> PauseOutcome: ...


class FastPathPauseExecutor:
    def __init__(self, client: FastPathClient):
        self._client = client

    def pause(self, candidate: SandboxCandidate) -> PauseOutcome:
        request_id = f"{IDLE_PAUSE_REQUEST_ID_PREFIX}{candidate.sandbox_id}"
        try:
            self._client.pause_sandbox(
                candidate.namespace,
                candidate.sandbox_id,
                expected_uid=candidate.uid,
                request_id=request_id,
            )
        except (FastPathFailedPrecondition, FastPathConflict) as exc:
            # "Durable state moved under us" for the sweeper: the pause fence
            # or an idempotency conflict. Drop; the next sweep re-evaluates.
            logger.info(
                f"idle_pause pause fence rejected sandbox_id={candidate.sandbox_id} "
                f"code={exc.code}"
            )
            return PauseOutcome.STATE_CHANGED
        except FastPathNotFound:
            return PauseOutcome.NOT_FOUND
        except FastPathUnavailable as exc:
            logger.warning(
                f"idle_pause pause unavailable sandbox_id={candidate.sandbox_id} "
                f"code={exc.code}"
            )
            return PauseOutcome.UNAVAILABLE
        except FastPathError as exc:
            logger.warning(
                f"idle_pause pause failed sandbox_id={candidate.sandbox_id} "
                f"code={exc.code} message={exc.message}"
            )
            return PauseOutcome.FAILED
        return PauseOutcome.ACCEPTED


__all__ = ["FastPathPauseExecutor", "PauseExecutor", "PauseOutcome"]
