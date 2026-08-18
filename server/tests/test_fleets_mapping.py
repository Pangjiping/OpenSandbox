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

"""Unit tests for fleets create/status mapping (OSEP-0007 simplified create)."""

# pyright: reportAttributeAccessIssue=false
# protobuf-generated modules expose dynamic attributes.
from datetime import datetime, timezone

import pytest

from opensandbox_server.api.schema import (
    CredentialProxyConfig,
    ImageSpec,
    NetworkPolicy,
    NetworkRule,
    PlatformSpec,
    ResourceLimits,
    Volume,
)
from opensandbox_server.services.fleets.create_mapping import (
    RENEW_EXTEND_SECONDS_METADATA_KEY,
    UnsupportedFieldError,
    map_create_request,
)
from opensandbox_server.services.fleets.generated import fastpath_pb2 as pb2
from opensandbox_server.services.fleets.status_mapping import (
    RESERVED_METADATA_KEYS,
    map_sandbox,
    map_state,
)

NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
EXPECTED_EXPIRY = int(NOW.timestamp()) + 3600


def _host_volume():
    from opensandbox_server.api.schema import Host

    return Volume(name="data", host=Host(path="/tmp/data"), mountPath="/data")


def _auth():
    from opensandbox_server.api.schema import ImageAuth

    return ImageAuth(username="u", password="p")


def _base_request(**overrides):
    from opensandbox_server.api.schema import CreateSandboxRequest

    payload = {
        "image": ImageSpec(uri="python:3.11"),
        "entrypoint": ["python", "-m", "http.server"],
        "timeout": 3600,
        "resource_limits": ResourceLimits(root={"cpu": "500m"}),
    }
    payload.update(overrides)
    return CreateSandboxRequest(**payload)


# -- create mapping -----------------------------------------------------------


def test_map_create_request_maps_core_fields():
    request = _base_request(
        env={"PYTHONUNBUFFERED": "1"},
        metadata={"team": "agents"},
        extensions={"poolRef": "ml-pool"},
    )

    create = map_create_request(request, "sbx-1", "ns-1", now=NOW)

    assert create.request_id == "sbx-1"
    assert create.namespace == "ns-1"
    assert create.image == "python:3.11"
    assert create.command == ["python", "-m", "http.server"]
    assert create.envs["PYTHONUNBUFFERED"] == "1"
    assert create.metadata["team"] == "agents"
    assert create.pool_ref == "ml-pool"
    assert create.expires_at_unix_seconds == EXPECTED_EXPIRY


def test_map_create_request_defaults_pool_ref():
    request = _base_request()
    create = map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert create.pool_ref == "default-pool"


def test_map_create_request_renew_extension_goes_to_reserved_metadata():
    request = _base_request(extensions={"access.renew.extend.seconds": "300"})
    create = map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert create.metadata[RENEW_EXTEND_SECONDS_METADATA_KEY] == "300"


@pytest.mark.parametrize(
    "field_name,payload",
    [
        # snapshotId is mutually exclusive with image at the schema layer, so
        # build the request image-less to reach the fleets mapping rejection.
        ("snapshotId", {"image": None, "snapshot_id": "snap-1"}),
        ("platform", {"platform": PlatformSpec(os="linux", arch="amd64")}),
        (
            "resourceRequests",
            {"resource_requests": ResourceLimits(root={"cpu": "1"})},
        ),
        (
            "credentialProxy",
            {
                # schema requires networkPolicy when credentialProxy is
                # enabled; the fleets mapping still rejects credentialProxy
                # first.
                "credential_proxy": CredentialProxyConfig(enabled=True),
                "network_policy": NetworkPolicy(
                    egress=[NetworkRule(action="allow", target="a.com")]
                ),
            },
        ),
        (
            "networkPolicy",
            {"network_policy": NetworkPolicy(egress=[NetworkRule(action="allow", target="a.com")])},
        ),
        ("secureAccess", {"secure_access": True}),
        ("volumes", {"volumes": [_host_volume()]}),
    ],
)
def test_map_create_request_rejects_unsupported_fields(field_name, payload):
    request = _base_request(**payload)
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert exc_info.value.field == field_name


def test_map_create_request_rejects_image_auth():
    request = _base_request(image=ImageSpec(uri="private/reg:1", auth=_auth()))
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert exc_info.value.field == "image.auth"


def test_map_create_request_rejects_missing_image_even_with_pool_ref():
    # A fast-sandbox SandboxPool does not define the workload image.
    request = _base_request(image=None, extensions={"poolRef": "ml-pool"})
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert exc_info.value.field == "image"


def test_map_create_request_rejects_null_timeout():
    request = _base_request(timeout=None)
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert exc_info.value.field == "timeout"


def test_map_create_request_rejects_null_env_value():
    request = _base_request(env={"EMPTY": None})
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert exc_info.value.field == "env"


def test_map_create_request_rejects_unknown_extension_key():
    request = _base_request(extensions={"bootstrap.execd.isolation": "per-slot"})
    with pytest.raises(UnsupportedFieldError) as exc_info:
        map_create_request(request, "sbx-1", "ns-1", now=NOW)
    assert "extensions" in exc_info.value.field


# -- status mapping -----------------------------------------------------------


def _info(**overrides):
    info = pb2.SandboxInfo(
        sandbox_uid="uid-1",
        sandbox_name="sbx-1",
        namespace="ns-1",
        runtime_state="Ready",
        data_plane_state="Ready",
        image="python:3.11",
        created_at_unix_seconds=int(NOW.timestamp()),
    )
    if "expires_at_unix_seconds" in overrides:
        info.expires_at_unix_seconds = overrides["expires_at_unix_seconds"]
    if "metadata" in overrides:
        info.metadata.update(overrides["metadata"])
    if "runtime_state" in overrides:
        info.runtime_state = overrides["runtime_state"]
    if "data_plane_state" in overrides:
        info.data_plane_state = overrides["data_plane_state"]
    return info


@pytest.mark.parametrize(
    "runtime,data_plane,expected",
    [
        ("Ready", "Ready", "Running"),
        ("Ready", "", "Pending"),
        ("Pending", "", "Pending"),
        ("Creating", "", "Pending"),
        ("Draining", "", "Stopping"),
        ("Stopped", "", "Terminated"),
        ("Failed", "", "Failed"),
        ("Unavailable", "", "Failed"),
        ("", "", "Pending"),
    ],
)
def test_map_state_matrix(runtime, data_plane, expected):
    assert map_state(_info(runtime_state=runtime, data_plane_state=data_plane)) == expected


def test_map_sandbox_builds_public_model():
    sandbox = map_sandbox(
        _info(
            expires_at_unix_seconds=EXPECTED_EXPIRY,
            metadata={"team": "agents", RENEW_EXTEND_SECONDS_METADATA_KEY: "300"},
        )
    )

    assert sandbox.id == "sbx-1"
    assert sandbox.image is not None
    assert sandbox.image.uri == "python:3.11"
    assert sandbox.status.state == "Running"
    assert sandbox.metadata == {"team": "agents"}
    assert sandbox.expires_at == datetime.fromtimestamp(EXPECTED_EXPIRY, tz=timezone.utc)
    assert sandbox.created_at == NOW


def test_map_sandbox_terminated_on_expired_retained_crd():
    sandbox = map_sandbox(_info(runtime_state="Stopped"))
    assert sandbox.status.state == "Terminated"
    assert sandbox.status.reason == "Expired"


def test_map_sandbox_omits_empty_metadata_and_expiry():
    sandbox = map_sandbox(_info())
    assert sandbox.metadata is None
    assert sandbox.expires_at is None


def test_reserved_metadata_keys_are_defined():
    assert RENEW_EXTEND_SECONDS_METADATA_KEY in RESERVED_METADATA_KEYS
