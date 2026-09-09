"""Exercise real adapters and readiness loops with HTTP auth responses."""

from datetime import timedelta

import httpx
import pytest

from opensandbox.config import ConnectionConfig
from opensandbox.config.connection_sync import ConnectionConfigSync
from opensandbox.exceptions import SandboxApiException
from opensandbox.sandbox import Sandbox
from opensandbox.sync.sandbox import SandboxSync


def responder(status, calls, recover=False):
    def handle(request):
        if request.method == "POST":
            return httpx.Response(204)
        if request.url.path == "/ping":
            calls.append(request.url.path)
            assert request.headers["X-EXECD-ACCESS-TOKEN"] == "invalid"
            if recover and len(calls) > 1:
                return httpx.Response(200)
            return httpx.Response(
                status,
                json={"code": "PROBE_ERROR", "message": "probe rejected"},
                headers={"X-Request-ID": "auth-probe-123"},
            )
        return httpx.Response(200, json={
            "endpoint": "localhost:44772",
            "headers": {"X-EXECD-ACCESS-TOKEN": "invalid"},
        })
    return handle


def assert_auth_error(exc, status, calls):
    assert exc.status_code == status
    assert exc.error.code == "UNEXPECTED_RESPONSE"
    assert exc.request_id == "auth-probe-123"
    assert "probe rejected" in str(exc)
    assert calls == ["/ping"]


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("resume", [False, True])
@pytest.mark.asyncio
async def test_async_auth_response_fails_fast(status, resume):
    calls = []
    config = ConnectionConfig(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls)))
    method = Sandbox.resume if resume else Sandbox.connect
    with pytest.raises(SandboxApiException) as error:
        await method("sb", connection_config=config, connect_timeout=timedelta(seconds=.2)) if not resume else await method("sb", connection_config=config, resume_timeout=timedelta(seconds=.2))
    assert_auth_error(error.value, status, calls)


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("resume", [False, True])
def test_sync_auth_response_fails_fast(status, resume):
    calls = []
    config = ConnectionConfigSync(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls)))
    method = SandboxSync.resume if resume else SandboxSync.connect
    kwargs = {"resume_timeout" if resume else "connect_timeout": timedelta(seconds=.2)}
    with pytest.raises(SandboxApiException) as error:
        method("sb", connection_config=config, **kwargs)
    assert_auth_error(error.value, status, calls)


@pytest.mark.parametrize("status", [429, 503])
@pytest.mark.asyncio
async def test_async_transient_response_recovers(status):
    calls = []
    config = ConnectionConfig(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls, True)))
    sb = await Sandbox.connect("sb", connection_config=config, health_check_polling_interval=timedelta(milliseconds=1))
    assert calls == ["/ping", "/ping"]
    await sb.close()


@pytest.mark.parametrize("status", [429, 503])
def test_sync_transient_response_recovers(status):
    calls = []
    config = ConnectionConfigSync(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls, True)))
    sb = SandboxSync.connect("sb", connection_config=config, health_check_polling_interval=timedelta(milliseconds=1))
    assert calls == ["/ping", "/ping"]
    sb.close()


@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.asyncio
async def test_async_is_healthy_still_returns_false(status):
    calls = []
    config = ConnectionConfig(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls)))
    sb = await Sandbox.connect("sb", connection_config=config, skip_health_check=True)
    assert await sb.is_healthy() is False
    await sb.close()


@pytest.mark.parametrize("status", [401, 403])
def test_sync_is_healthy_still_returns_false(status):
    calls = []
    config = ConnectionConfigSync(domain="localhost:8080", transport=httpx.MockTransport(responder(status, calls)))
    sb = SandboxSync.connect("sb", connection_config=config, skip_health_check=True)
    assert sb.is_healthy() is False
    sb.close()
