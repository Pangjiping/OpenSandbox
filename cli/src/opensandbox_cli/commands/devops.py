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

"""DevOps diagnostics commands: logs, inspect, events, summary."""

from __future__ import annotations

import click
import httpx

from opensandbox_cli.client import ClientContext
from opensandbox_cli.utils import handle_errors


def _devops_url(obj: ClientContext, sandbox_id: str, endpoint: str) -> str:
    """Build the full URL for a DevOps diagnostics endpoint."""
    cfg = obj.resolved_config
    protocol = cfg.get("protocol", "http")
    domain = cfg.get("domain", "localhost:8080")
    return f"{protocol}://{domain}/v1/sandboxes/{sandbox_id}/diagnostics/{endpoint}"


def _devops_headers(obj: ClientContext) -> dict[str, str]:
    """Build request headers with optional API key."""
    cfg = obj.resolved_config
    headers: dict[str, str] = {"Accept": "text/plain"}
    api_key = cfg.get("api_key")
    if api_key:
        headers["OPEN-SANDBOX-API-KEY"] = api_key
    return headers


def _fetch_plain_text(obj: ClientContext, sandbox_id: str, endpoint: str, params: dict | None = None) -> str:
    """Fetch a diagnostics endpoint and return the plain-text body."""
    sandbox_id = obj.resolve_sandbox_id(sandbox_id)
    url = _devops_url(obj, sandbox_id, endpoint)
    headers = _devops_headers(obj)
    cfg = obj.resolved_config
    timeout = cfg.get("request_timeout", 30)

    resp = httpx.get(url, headers=headers, params=params, timeout=timeout)
    if resp.status_code == 404:
        raise click.ClickException(f"Sandbox '{sandbox_id}' not found.")
    resp.raise_for_status()
    return resp.text


@click.group("devops", invoke_without_command=True)
@click.pass_context
def devops_group(ctx: click.Context) -> None:
    """DevOps diagnostics for sandbox troubleshooting."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---- logs ----------------------------------------------------------------

@devops_group.command("logs")
@click.argument("sandbox_id")
@click.option("--tail", "-n", type=int, default=100, show_default=True, help="Number of trailing log lines.")
@click.option("--since", "-s", default=None, help="Only logs newer than this duration (e.g. 10m, 1h).")
@click.pass_obj
@handle_errors
def devops_logs(obj: ClientContext, sandbox_id: str, tail: int, since: str | None) -> None:
    """Retrieve container logs for a sandbox."""
    params: dict = {"tail": tail}
    if since:
        params["since"] = since
    text = _fetch_plain_text(obj, sandbox_id, "logs", params=params)
    click.echo(text)


# ---- inspect -------------------------------------------------------------

@devops_group.command("inspect")
@click.argument("sandbox_id")
@click.pass_obj
@handle_errors
def devops_inspect(obj: ClientContext, sandbox_id: str) -> None:
    """Retrieve detailed container/pod inspection info."""
    text = _fetch_plain_text(obj, sandbox_id, "inspect")
    click.echo(text)


# ---- events --------------------------------------------------------------

@devops_group.command("events")
@click.argument("sandbox_id")
@click.option("--limit", "-l", type=int, default=50, show_default=True, help="Maximum number of events.")
@click.pass_obj
@handle_errors
def devops_events(obj: ClientContext, sandbox_id: str, limit: int) -> None:
    """Retrieve events related to a sandbox."""
    params: dict = {"limit": limit}
    text = _fetch_plain_text(obj, sandbox_id, "events", params=params)
    click.echo(text)


# ---- summary -------------------------------------------------------------

@devops_group.command("summary")
@click.argument("sandbox_id")
@click.option("--tail", "-n", type=int, default=50, show_default=True, help="Number of trailing log lines.")
@click.option("--event-limit", type=int, default=20, show_default=True, help="Maximum number of events.")
@click.pass_obj
@handle_errors
def devops_summary(obj: ClientContext, sandbox_id: str, tail: int, event_limit: int) -> None:
    """One-shot diagnostics: inspect + events + logs combined."""
    params: dict = {"tail": tail, "event_limit": event_limit}
    text = _fetch_plain_text(obj, sandbox_id, "summary", params=params)
    click.echo(text)
