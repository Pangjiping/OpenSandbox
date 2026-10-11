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

"""OSEP-0024 idle-pause constants.

Redis key prefixes are a code-level convention fixed identically on the
ingress producer and the server consumer — deliberately not exposed as a
config knob: a prefix mismatch could only delay pauses (via tombstones),
never corrupt decisions (see OSEP-0024, Activity Tracking).
"""

# Activity observation: value = Unix milliseconds of the last observation,
# written with monotonic-max semantics and EX activity_ttl_seconds.
ACTIVITY_KEY_PREFIX = "opensandbox:activity"

# Unknown-activity tombstone: first sweeper observation of a missing activity
# key records the wall-clock time here; the sandbox becomes idle-eligible only
# once the tombstone itself has existed for >= X.
UNKNOWN_TOMBSTONE_PREFIX = "opensandbox:idlep:unknown"

# Per-sandbox pause admission lock (SET NX EX); TTL is the primary release.
LOCK_PREFIX = "opensandbox:idlep:lock"

# Validation bounds for idlePolicy.idleTimeoutSeconds (X), enforced where the
# create field is accepted; X <= activity_ttl_seconds is checked against the
# server config at the same place.
IDLE_TIMEOUT_MIN_SECONDS = 30
IDLE_TIMEOUT_MAX_SECONDS = 86400

# Validation bounds for idlePolicy.activeProbe.timeoutSeconds.
PROBE_TIMEOUT_MIN_SECONDS = 1
PROBE_TIMEOUT_MAX_SECONDS = 10
DEFAULT_PROBE_TIMEOUT_SECONDS = 2

# The only idle action in this revision; the enum value exists so a future
# action (e.g. terminate) stays additive.
ON_IDLE_ACTION_PAUSE = "pause"

# Idempotent PauseSandbox request_id for sweeper-issued pauses: replays of the
# same idle episode are deduplicated FastPath-side.
IDLE_PAUSE_REQUEST_ID_PREFIX = "idlepause-"
