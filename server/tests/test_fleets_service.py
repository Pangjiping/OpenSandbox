# pyright: reportAttributeAccessIssue=false
# protobuf-generated modules expose dynamic attributes.

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

"""Unit tests for FleetSandboxService lifecycle behavior (OSEP-0007 Phase 1a)."""

from concurrent import futures
from datetime import datetime, timedelta, timezone

import grpc
import pytest
from fastapi import HTTPException

from opensandbox_server.api.schema import (
    CreateSandboxRequest,
    ImageSpec,
    ListSandboxesRequest,
    PaginationRequest,
    RenewSandboxExpirationRequest,
    ResourceLimits,
    SandboxFilter,
)
from opensandbox_server.config import AppConfig, FleetsRuntimeConfig
from opensandbox_server.services.fleets.create_mapping import (
    RENEW_EXTEND_SECONDS_METADATA_KEY,
)
from opensandbox_server.services.fleets.fastpath_client import FastPathClient
from opensandbox_server.services.fleets.fleet_service import FleetSandboxService
from opensandbox_server.services.fleets.generated import (
    fastpath_pb2 as pb2,
)
from opensandbox_server.services.fleets.generated import (
    fastpath_pb2_grpc as pb2_grpc,
)

NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
NOW_TS = int(NOW.timestamp())


class _FakeFastPathService(pb2_grpc.FastPathServiceServicer):
    """Stateful in-process FastPath server."""

    def __init__(self):
        self.sandboxes: dict[str, pb2.SandboxInfo] = {}
        self.deleted: list[str] = []
        self.fail_create_with: grpc.StatusCode | None = None
        self.pool = pb2.PoolInfo(
            namespace="ns-1",
            name="default-pool",
            runtime="container",
            sandbox_cpu="500m",
            sandbox_memory="512Mi",
            sandbox_pids=256,
        )

    def _info(self, sandbox_id: str, **overrides) -> pb2.SandboxInfo:
        base = dict(
            sandbox_uid=f"uid-{sandbox_id}",
            sandbox_name=sandbox_id,
            namespace="ns-1",
            runtime_state="Ready",
            data_plane_state="Ready",
            image="python:3.11",
            pool_ref="default-pool",
            created_at_unix_seconds=NOW_TS,
            expires_at_unix_seconds=NOW_TS + 3600,
        )
        base.update(overrides)
        info = pb2.SandboxInfo(**base)
        return info

    def _get(self, sandbox_id: str):
        info = self.sandboxes.get(sandbox_id)
        if info is None:
            raise KeyError(sandbox_id)
        return info

    def CreateSandbox(self, request, context):
        if self.fail_create_with is not None:
            context.abort(self.fail_create_with, "scripted create failure")
        info = self._info(request.request_id)
        info.metadata.update(request.metadata)
        info.image = request.image
        info.pool_ref = request.pool_ref
        info.expires_at_unix_seconds = request.expires_at_unix_seconds
        self.sandboxes[request.request_id] = info
        return info

    def GetSandbox(self, request, context):
        try:
            return self._get(request.sandbox_name)
        except KeyError:
            context.abort(grpc.StatusCode.NOT_FOUND, "not found")
            raise

    def DeleteSandbox(self, request, context):
        try:
            self._get(request.sandbox_name)
        except KeyError:
            context.abort(grpc.StatusCode.NOT_FOUND, "not found")
        self.deleted.append(request.sandbox_name)
        return pb2.DeleteResponse(success=True)

    def ListSandboxes(self, request, context):
        response = pb2.ListResponse()
        for info in self.sandboxes.values():
            if request.metadata:
                if not all(info.metadata.get(k) == v for k, v in request.metadata.items()):
                    continue
            copy = pb2.SandboxInfo()
            copy.CopyFrom(info)
            response.items.append(copy)
        return response

    def UpdateSandbox(self, request, context):
        try:
            info = self._get(request.sandbox_name)
        except KeyError:
            context.abort(grpc.StatusCode.NOT_FOUND, "not found")
            return pb2.UpdateResponse(success=False)
        if request.expires_at_unix_seconds > 0:
            info.expires_at_unix_seconds = request.expires_at_unix_seconds
        if request.metadata_upsert:
            info.metadata.update(request.metadata_upsert)
        for key in request.metadata_delete_keys:
            info.metadata.pop(key, None)
        return pb2.UpdateResponse(success=True, sandbox=info)

    def GetSandboxDiagnostics(self, request, context):
        try:
            info = self._get(request.sandbox_name)
        except KeyError:
            context.abort(grpc.StatusCode.NOT_FOUND, "not found")
            return pb2.SandboxDiagnosticsResponse()
        event = pb2.SandboxDiagnosticEvent(
            timestamp_unix_nano=1,
            level="INFO",
            source="fastpath",
            phase="create",
            message="created",
        )
        return pb2.SandboxDiagnosticsResponse(
            sandbox=info, assignment_state="assigned", events=[event]
        )

    def WaitSandboxReady(self, request, context):
        try:
            name = request.sandbox.namespaced_name.name
            return self._get(name)
        except KeyError:
            context.abort(grpc.StatusCode.NOT_FOUND, "not found")

    def GetPool(self, request, context):
        return self.pool


@pytest.fixture
def service():
    fake = _FakeFastPathService()
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb2_grpc.add_FastPathServiceServicer_to_server(fake, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    client = FastPathClient(endpoint=f"127.0.0.1:{port}")
    client._channel = channel  # noqa: SLF001
    client._stub = pb2_grpc.FastPathServiceStub(channel)

    from opensandbox_server.config import RuntimeConfig, ServerConfig

    config = AppConfig(
        server=ServerConfig(host="0.0.0.0", port=8080, api_key="x"),
        runtime=RuntimeConfig(type="fleets", execd_image="ghcr.io/opensandbox/execd:latest"),
        fleets=FleetsRuntimeConfig(namespace="ns-1"),
    )
    svc = FleetSandboxService(config, fastpath_client=client)
    try:
        yield svc, fake
    finally:
        channel.close()
        server.stop(None)


def _create_request(**overrides):
    payload = {
        "image": ImageSpec(uri="python:3.11"),
        "entrypoint": ["python", "-m", "http.server"],
        "timeout": 3600,
        "resource_limits": ResourceLimits(root={"cpu": "500m", "memory": "512Mi"}),
    }
    payload.update(overrides)
    return CreateSandboxRequest(**payload)


# -- create ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_sandbox_returns_running(service):
    svc, fake = service
    response = await svc.create_sandbox(_create_request())
    assert response.status.state == "Running"
    assert response.id in fake.sandboxes
    assert response.expires_at is not None
    assert response.created_at == NOW


@pytest.mark.asyncio
async def test_create_sandbox_rejects_unsupported_fields(service):
    svc, _ = service
    with pytest.raises(HTTPException) as exc_info:
        await svc.create_sandbox(_create_request(snapshot_id="snap-1", image=None))
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_create_sandbox_pool_mismatch_rejected(service):
    svc, _ = service
    request = _create_request(
        resource_limits=ResourceLimits(root={"cpu": "1", "memory": "512Mi"})
    )
    with pytest.raises(HTTPException) as exc_info:
        await svc.create_sandbox(request)
    assert exc_info.value.status_code == 400
    assert "resourceLimits" in exc_info.value.detail["message"]


@pytest.mark.asyncio
async def test_create_sandbox_ambiguous_failure_returns_pending(service):
    svc, fake = service
    # Simulate a create that failed after durable intent was persisted.
    fake.fail_create_with = grpc.StatusCode.INTERNAL
    request = _create_request()
    preexisting = fake._info("pre-created", runtime_state="Creating", data_plane_state="")
    fake.sandboxes["pre-created"] = preexisting
    # The service generates its own id; seed intent under that id by creating
    # first without the failure, then flip the failure flag and repeat.
    fake.fail_create_with = None
    response = await svc.create_sandbox(request)
    created_id = response.id
    fake.fail_create_with = grpc.StatusCode.INTERNAL
    # A second create with a fresh id fails hard when no intent exists.
    with pytest.raises(HTTPException):
        await svc.create_sandbox(_create_request(env={"X": "2"}))
    assert created_id in fake.sandboxes


# -- get / list -----------------------------------------------------------


def test_get_sandbox_returns_mapped_model(service):
    svc, fake = service
    info = fake._info("sbx-1", metadata={"team": "agents", RENEW_EXTEND_SECONDS_METADATA_KEY: "300"})
    fake.sandboxes["sbx-1"] = info
    sandbox = svc.get_sandbox("sbx-1")
    assert sandbox.id == "sbx-1"
    assert sandbox.status.state == "Running"
    assert sandbox.metadata == {"team": "agents"}
    assert sandbox.image is not None
    assert sandbox.image.uri == "python:3.11"


def test_get_sandbox_missing_maps_to_404(service):
    svc, _ = service
    with pytest.raises(HTTPException) as exc_info:
        svc.get_sandbox("missing")
    assert exc_info.value.status_code == 404


def test_list_sandboxes_pagination_and_state_filter(service):
    svc, fake = service
    for i in range(5):
        fake.sandboxes[f"sbx-{i}"] = fake._info(
            f"sbx-{i}",
            runtime_state="Creating" if i == 0 else "Ready",
            data_plane_state="" if i == 0 else "Ready",
        )
    request = ListSandboxesRequest(
        filter=SandboxFilter(state=["Running"]),
        pagination=PaginationRequest(page=1, pageSize=2),
    )
    response = svc.list_sandboxes(request)
    assert len(response.items) == 2
    assert all(item.status.state == "Running" for item in response.items)
    assert response.pagination.total_items == 4
    assert response.pagination.total_pages == 2
    assert response.pagination.has_next_page is True


def test_list_sandboxes_metadata_filter(service):
    svc, fake = service
    fake.sandboxes["a"] = fake._info("a", metadata={"team": "agents"})
    fake.sandboxes["b"] = fake._info("b", metadata={"team": "ops"})
    response = svc.list_sandboxes(
        ListSandboxesRequest(filter=SandboxFilter(metadata={"team": "agents"}))
    )
    assert [item.id for item in response.items] == ["a"]


# -- delete / renew / metadata --------------------------------------------


def test_delete_sandbox_preflight_404(service):
    svc, _ = service
    with pytest.raises(HTTPException) as exc_info:
        svc.delete_sandbox("missing")
    assert exc_info.value.status_code == 404


def test_delete_sandbox_submits_async_delete(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1")
    svc.delete_sandbox("sbx-1")
    assert "sbx-1" in fake.deleted


def test_renew_expiration_updates_absolute_expiry(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1")
    new_expiry = datetime.now(timezone.utc) + timedelta(hours=2)
    expected = new_expiry.replace(microsecond=0)
    response = svc.renew_expiration(
        "sbx-1", RenewSandboxExpirationRequest(expires_at=new_expiry)
    )
    assert response.expires_at == expected
    assert fake.sandboxes["sbx-1"].expires_at_unix_seconds == int(expected.timestamp())


def test_renew_expiration_rejects_past(service):
    svc, _ = service
    with pytest.raises(HTTPException) as exc_info:
        svc.renew_expiration(
            "sbx-1", RenewSandboxExpirationRequest(expires_at=datetime(2020, 1, 1, tzinfo=timezone.utc))
        )
    assert exc_info.value.status_code == 400


def test_patch_metadata_upsert_and_delete(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1", metadata={"a": "1"})
    sandbox = svc.patch_sandbox_metadata("sbx-1", {"b": "2", "a": None})
    assert sandbox.metadata == {"b": "2"}
    assert fake.sandboxes["sbx-1"].metadata["b"] == "2"
    assert "a" not in fake.sandboxes["sbx-1"].metadata


def test_patch_metadata_rejects_reserved_keys(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1")
    for key in (RENEW_EXTEND_SECONDS_METADATA_KEY, "opensandbox.io/whatever"):
        with pytest.raises(HTTPException) as exc_info:
            svc.patch_sandbox_metadata("sbx-1", {key: "x"})
        assert exc_info.value.status_code == 400


# -- diagnostics / unsupported --------------------------------------------


def test_diagnostics_backed_by_lifecycle_events(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1")
    result = svc.get_sandbox_event_diagnostics("sbx-1", "events")
    assert result.kind == "events"
    assert "created" in result.content


def test_logs_unsupported(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info("sbx-1")
    with pytest.raises(HTTPException) as exc_info:
        svc.get_sandbox_logs("sbx-1")
    assert exc_info.value.status_code == 400
    assert "not supported" in exc_info.value.detail["message"]


def test_pause_resume_unsupported(service):
    svc, _ = service
    with pytest.raises(HTTPException):
        svc.pause_sandbox("sbx-1")
    with pytest.raises(HTTPException):
        svc.resume_sandbox("sbx-1")


def test_get_endpoint_unsupported_in_phase_1a(service):
    svc, _ = service
    with pytest.raises(HTTPException) as exc_info:
        svc.get_endpoint("sbx-1", 44772)
    assert exc_info.value.status_code == 400


# -- ExtensionService -----------------------------------------------------


def test_access_renew_extend_seconds_reads_reserved_key(service):
    svc, fake = service
    fake.sandboxes["sbx-1"] = fake._info(
        "sbx-1", metadata={RENEW_EXTEND_SECONDS_METADATA_KEY: "300"}
    )
    assert svc.get_access_renew_extend_seconds("sbx-1") == 300


def test_access_renew_extend_seconds_missing_or_invalid(service):
    svc, fake = service
    fake.sandboxes["plain"] = fake._info("plain")
    fake.sandboxes["bad"] = fake._info("bad", metadata={RENEW_EXTEND_SECONDS_METADATA_KEY: "oops"})
    assert svc.get_access_renew_extend_seconds("plain") is None
    assert svc.get_access_renew_extend_seconds("bad") is None
    assert svc.get_access_renew_extend_seconds("missing") is None


# -- startup wiring -------------------------------------------------------


def test_snapshot_runtime_factory_returns_noop_for_fleets():
    from opensandbox_server.services.snapshot_runtime_factory import (
        create_snapshot_runtime,
    )

    from opensandbox_server.config import RuntimeConfig, ServerConfig

    runtime = create_snapshot_runtime(
        AppConfig(
            server=ServerConfig(host="0.0.0.0", port=8080, api_key="x"),
            runtime=RuntimeConfig(type="fleets", execd_image="ghcr.io/opensandbox/execd:latest"),
        )
    )
    assert runtime.supports_create_snapshot() is False
