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

"""OSEP-0024 idle-pause constants (shared with the ingress, not a config knob)."""

# Value is Unix millis of the last observation (monotonic max, EX activity_ttl).
ACTIVITY_KEY_PREFIX = "opensandbox:activity"

# First observation of a missing activity key records the time here.
UNKNOWN_TOMBSTONE_PREFIX = "opensandbox:idlep:unknown"

LOCK_PREFIX = "opensandbox:idlep:lock"

# idlePolicy.idleTimeoutSeconds (X) bounds, enforced at create time.
IDLE_TIMEOUT_MIN_SECONDS = 30
IDLE_TIMEOUT_MAX_SECONDS = 86400

# idlePolicy.activeProbe.timeoutSeconds bounds.
PROBE_TIMEOUT_MIN_SECONDS = 1
PROBE_TIMEOUT_MAX_SECONDS = 10
DEFAULT_PROBE_TIMEOUT_SECONDS = 2

# Only action in this revision; the field exists so future actions stay additive.
ON_IDLE_ACTION_PAUSE = "pause"

# Idempotent PauseSandbox request id prefix; FastPath deduplicates replays.
IDLE_PAUSE_REQUEST_ID_PREFIX = "idlepause-"
