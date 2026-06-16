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
Isolated session service interface.

Protocol for namespace-isolated execution operations (OSEP-0013).
"""

from typing import Protocol

from opensandbox.models.execd import Execution, ExecutionHandlers
from opensandbox.models.isolated import (
    CreateIsolatedSessionRequest,
    IsolatedCapabilities,
    IsolatedRunOpts,
    IsolatedSessionInfo,
    IsolatedSessionState,
)
from opensandbox.services.filesystem import Filesystem


class IsolationSession(Protocol):
    """Handle to a single isolated bash session."""

    @property
    def session_id(self) -> str: ...

    @property
    def info(self) -> IsolatedSessionInfo: ...

    @property
    def files(self) -> Filesystem: ...

    async def run(
        self,
        code: str,
        *,
        opts: IsolatedRunOpts | None = None,
        handlers: ExecutionHandlers | None = None,
    ) -> Execution: ...

    async def get(self) -> IsolatedSessionState: ...

    async def delete(self) -> None: ...


class IsolationService(Protocol):
    """Service for managing namespace-isolated bash sessions."""

    async def create(
        self, request: CreateIsolatedSessionRequest
    ) -> IsolationSession: ...

    async def capabilities(self) -> IsolatedCapabilities: ...
