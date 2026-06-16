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
Synchronous isolated session service interface.
"""

from typing import Any, Protocol

from opensandbox.models.execd import Execution
from opensandbox.models.execd_sync import ExecutionHandlersSync
from opensandbox.models.isolated import (
    CreateIsolatedSessionRequest,
    IsolatedCapabilities,
    IsolatedRunOpts,
    IsolatedSessionInfo,
    IsolatedSessionState,
)


class IsolationSessionSync(Protocol):
    """Sync handle to a single isolated session."""

    @property
    def session_id(self) -> str: ...

    @property
    def info(self) -> IsolatedSessionInfo: ...

    @property
    def files(self) -> Any: ...

    def run(
        self,
        code: str,
        *,
        opts: IsolatedRunOpts | None = None,
        handlers: ExecutionHandlersSync | None = None,
    ) -> Execution: ...

    def get(self) -> IsolatedSessionState: ...

    def delete(self) -> None: ...


class IsolationServiceSync(Protocol):
    """Sync service for managing namespace-isolated bash sessions."""

    def create(
        self, request: CreateIsolatedSessionRequest
    ) -> IsolationSessionSync: ...

    def capabilities(self) -> IsolatedCapabilities: ...
