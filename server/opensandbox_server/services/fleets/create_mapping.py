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

"""Map OpenSandbox CreateSandboxRequest into fast-sandbox FastPath v2 CreateRequest.

The fleets backend accepts a strict subset of the public create contract.
Unsupported fields are rejected with a clear error instead of being silently
ignored (see OSEP-0007 "Simplified Create").
"""

# pyright: reportAttributeAccessIssue=false
# protobuf-generated modules expose dynamic attributes.
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from opensandbox_server.api.schema import CreateSandboxRequest
from opensandbox_server.services.fleets.generated import (
    fastpath_pb2 as pb2,
)

#: fleets-reserved FastPath metadata key persisting the renew-on-access
#: extension value. Stripped from public metadata and list filters.
RENEW_EXTEND_SECONDS_METADATA_KEY = "opensandbox.io/renew-extend-seconds"

#: Public extensions keys accepted by the fleets backend.
SUPPORTED_EXTENSION_KEYS = frozenset(
    {"poolRef", "access.renew.extend.seconds"}
)

#: FastPath CreateRequest has no nullable timeout; fleets requires an explicit one.
ERROR_TIMEOUT_REQUIRED = (
    "timeout is required on fleets: fast-sandbox persists an absolute "
    "expires_at in the first Create write and has no non-expiring sandboxes."
)


class UnsupportedFieldError(ValueError):
    """A CreateSandboxRequest field cannot be honored by the fleets backend."""

    def __init__(self, field: str, reason: str):
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


def map_create_request(
    request: CreateSandboxRequest,
    sandbox_id: str,
    namespace: str,
    *,
    default_pool_ref: str = "default-pool",
    now: Optional[datetime] = None,
) -> pb2.CreateRequest:
    """Map the accepted CreateSandboxRequest subset to a FastPath v2 CreateRequest.

    Raises UnsupportedFieldError for any field the shared-Fastlet model cannot
    honor. The caller supplies the OpenSandbox sandbox_id, which becomes the
    idempotency key (request_id) and the Sandbox CRD name.
    """
    _reject_unsupported_fields(request)

    image = request.image
    if image is None or not image.uri.strip():
        # A fast-sandbox SandboxPool defines Infra Components and resources,
        # not the workload image, so fleets rejects image-less requests even
        # when extensions.poolRef is set.
        raise UnsupportedFieldError("image", "a non-empty image.uri is required on fleets")

    if image.auth is not None:
        raise UnsupportedFieldError(
            "image.auth", "private-registry credentials are not carried to fast-sandbox"
        )

    if request.timeout is None:
        raise UnsupportedFieldError("timeout", ERROR_TIMEOUT_REQUIRED)

    if request.entrypoint is None:
        raise UnsupportedFieldError("entrypoint", "entrypoint is required when image is provided")

    now = now or datetime.now(timezone.utc)
    expires_at = int(now.timestamp()) + request.timeout

    create = pb2.CreateRequest(
        request_id=sandbox_id,
        namespace=namespace,
        image=image.uri,
        command=list(request.entrypoint),
        expires_at_unix_seconds=expires_at,
    )

    if request.env:
        for key, value in request.env.items():
            if value is None:
                raise UnsupportedFieldError(
                    "env",
                    f"null value for environment variable {key!r} is not supported "
                    "(FastPath v2 uses map<string,string>)",
                )
            create.envs[key] = value

    if request.metadata:
        create.metadata.update(request.metadata)

    extensions = request.extensions or {}
    pool_ref = extensions.get("poolRef")
    create.pool_ref = pool_ref or default_pool_ref

    renew_value = extensions.get("access.renew.extend.seconds")
    if renew_value is not None:
        create.metadata[RENEW_EXTEND_SECONDS_METADATA_KEY] = renew_value

    return create


def _reject_unsupported_fields(request: CreateSandboxRequest) -> None:
    """Reject pod-identity-dependent fields that have no shared-Fastlet meaning."""
    if request.snapshot_id:
        raise UnsupportedFieldError("snapshotId", "snapshots are not supported on fleets")
    if request.platform is not None:
        raise UnsupportedFieldError(
            "platform", "scheduling is per Fastlet pool, not per sandbox"
        )
    if request.resource_requests is not None:
        raise UnsupportedFieldError(
            "resourceRequests",
            "resources are fixed by SandboxPool.spec.sandboxResources",
        )
    if request.credential_proxy is not None and request.credential_proxy.enabled:
        raise UnsupportedFieldError(
            "credentialProxy",
            "credential proxy rides the per-pod egress sidecar, which does not "
            "exist in the shared-Fastlet model",
        )
    if request.volumes:
        raise UnsupportedFieldError(
            "volumes", "Fastlet child containers cannot receive dynamic mounts"
        )
    if request.network_policy is not None:
        raise UnsupportedFieldError(
            "networkPolicy",
            "per-sandbox egress enforcement is deferred to phase 1b; not supported in phase 1a",
        )
    if request.secure_access:
        raise UnsupportedFieldError(
            "secureAccess",
            "secure access on fleets is deferred to phase 1b; not supported in phase 1a",
        )
    for key in (request.extensions or {}):
        if key not in SUPPORTED_EXTENSION_KEYS:
            raise UnsupportedFieldError(
                f"extensions[{key!r}]",
                "extension keys are rejected unless explicitly supported by fleets",
            )
