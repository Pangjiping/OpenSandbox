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

"""Async Redis access to the shared activity keys and unknown-state tombstones.

The ingress (and later the server proxy path) are the push producers; the
server reads here and writes on lifecycle transitions (create, resume).
Failures raise to the caller, which fails toward *not pausing*.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

from opensandbox_server.integrations.idle_pause.constants import (
    ACTIVITY_KEY_PREFIX,
    UNKNOWN_TOMBSTONE_PREFIX,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis

# Monotonic max: out-of-order writes across replicas never regress the key.
_MONOTONIC_MAX_SCRIPT = """
local cur = redis.call('GET', KEYS[1])
local new = tonumber(ARGV[1])
if cur == false or tonumber(cur) < new then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
end
return 1
"""


def activity_key(sandbox_id: str) -> str:
    return f"{ACTIVITY_KEY_PREFIX}:{sandbox_id}"


def unknown_tombstone_key(sandbox_id: str) -> str:
    return f"{UNKNOWN_TOMBSTONE_PREFIX}:{sandbox_id}"


class ActivityRegistry:
    """Async Redis access to activity observations and unknown-state tombstones."""

    def __init__(self, client: "Redis", *, activity_ttl_seconds: int):
        self._client = client
        self._ttl = int(activity_ttl_seconds)
        self._max_script = self._client.register_script(_MONOTONIC_MAX_SCRIPT)

    @property
    def activity_ttl_seconds(self) -> int:
        return self._ttl

    async def ping(self) -> None:
        """Raise when Redis is unreachable (the sweep skips entirely)."""
        await self._client.ping()

    async def record(
        self, sandbox_id: str, *, now_ms: Optional[int] = None
    ) -> None:
        """Write one observation (monotonic max, EX ttl)."""
        timestamp = now_ms if now_ms is not None else _now_ms()
        await self._max_script(keys=[activity_key(sandbox_id)], args=[timestamp, self._ttl])

    async def read(self, sandbox_id: str) -> Optional[int]:
        """Last observation in Unix ms, or ``None`` when missing."""
        value = await self._client.get(activity_key(sandbox_id))
        return _parse_ms(value)

    async def read_many(self, sandbox_ids: list[str]) -> dict[str, Optional[int]]:
        if not sandbox_ids:
            return {}
        values = await self._client.mget([activity_key(sid) for sid in sandbox_ids])
        return {sid: _parse_ms(value) for sid, value in zip(sandbox_ids, values)}

    async def ensure_tombstone(
        self, sandbox_id: str, *, now_ms: Optional[int] = None, extra_ttl_seconds: int = 0
    ) -> None:
        """Record the first observation of unknown state (NX; never overwrites)."""
        timestamp = now_ms if now_ms is not None else _now_ms()
        ttl = self._ttl + max(0, extra_ttl_seconds)
        await self._client.set(
            unknown_tombstone_key(sandbox_id),
            timestamp,
            nx=True,
            ex=ttl,
        )

    async def read_tombstone(self, sandbox_id: str) -> Optional[int]:
        value = await self._client.get(unknown_tombstone_key(sandbox_id))
        return _parse_ms(value)

    async def clear_tombstone(self, sandbox_id: str) -> None:
        """Drop the tombstone once the activity key reappeared."""
        await self._client.delete(unknown_tombstone_key(sandbox_id))


def _parse_ms(value: object) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _now_ms() -> int:
    return time.time_ns() // 1_000_000
