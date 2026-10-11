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

"""OSEP-0024 auto-pause server tooling (fast-sandbox backend).

This package encapsulates the server-side building blocks of auto-pause and
wake-on-access: the idle policy model + reserved-metadata codec, the shared
Redis activity registry, the pause admission lock, the pure idle-decision
function, the candidate inventory and pause-executor abstractions, and the
idle sweeper that wires the gates together.

Wake-on-access itself lives in the ingress gateway; the server proxy path
(activity writes + parking) is a later phase.
"""

from opensandbox_server.integrations.idle_pause.activity import ActivityRegistry, activity_key
from opensandbox_server.integrations.idle_pause.decision import (
    IdleDecision,
    IdleVerdict,
    evaluate_idle,
)
from opensandbox_server.integrations.idle_pause.executor import (
    FastPathPauseExecutor,
    PauseExecutor,
    PauseOutcome,
)
from opensandbox_server.integrations.idle_pause.inventory import (
    FastSandboxInventory,
    SandboxCandidate,
    SandboxInventory,
)
from opensandbox_server.integrations.idle_pause.locking import PauseLockManager
from opensandbox_server.integrations.idle_pause.policy import (
    ActivityProbe,
    IDLE_POLICY_ANNOTATION_KEY,
    IdlePolicy,
    idle_policy_from_annotation,
    idle_policy_to_annotation,
    validate_idle_policy,
)
from opensandbox_server.integrations.idle_pause.sweeper import (
    IdlePauseSweeper,
    SweepStats,
    start_idle_pause_sweeper,
)

__all__ = [
    "ActivityProbe",
    "ActivityRegistry",
    "FastPathPauseExecutor",
    "FastSandboxInventory",
    "IDLE_POLICY_ANNOTATION_KEY",
    "IdleDecision",
    "IdlePauseSweeper",
    "IdlePolicy",
    "IdleVerdict",
    "PauseExecutor",
    "PauseLockManager",
    "PauseOutcome",
    "SandboxCandidate",
    "SandboxInventory",
    "SweepStats",
    "activity_key",
    "evaluate_idle",
    "idle_policy_from_annotation",
    "idle_policy_to_annotation",
    "start_idle_pause_sweeper",
    "validate_idle_policy",
]
