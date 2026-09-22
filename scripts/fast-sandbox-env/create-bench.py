#!/usr/bin/env python3
"""create-bench.py — fsb sandbox create-latency bench for the fast-sandbox-env
kind deployment, written against the OpenSandbox Python SDK.

Run AFTER `./integration-env.sh up`:

    cd OpenSandbox/tests/python
    uv run python ../../scripts/fast-sandbox-env/create-bench.py

Creates (or reuses) one Succeeded fsb template, then creates N sandboxes with
CONCURRENCY parallel runs. Each sample = Sandbox.create_from_template()
returning with execd /ping readiness (the SDK's built-in delivery criterion
through the signed gateway route); the sandbox is killed right after
readiness. Reports avg/p50/p90/p99/min/max.

Env:
  N=100  CONCURRENCY=10
  DOMAIN=127.0.0.1:18080  PROTOCOL=http  API_KEY=fast-sandbox-env
  TEMPLATE_ID=            reuse a Succeeded template (skip the build)
  SOURCE_IMAGE=ubuntu:22.04  PUBLISH=s3://sandbox-images/publish
  WARMUP=2                untimed warmup creates (first artifact pull)
  READY_TIMEOUT_COLD=900  first-create readiness budget (artifact pull)
  READY_TIMEOUT_WARM=300  readiness budget for warm creates
"""

import asyncio
import os
import statistics
import sys
import time
from datetime import timedelta

from opensandbox.config import ConnectionConfig
from opensandbox.manager import SandboxManager
from opensandbox.models.templates import (
    CreateTemplateRequest,
    TemplatePhase,
    TemplateReadiness,
)
from opensandbox.sandbox import Sandbox

DOMAIN = os.environ.get("DOMAIN", "127.0.0.1:18080")
PROTOCOL = os.environ.get("PROTOCOL", "http")
API_KEY = os.environ.get("API_KEY", "fast-sandbox-env")
N = int(os.environ.get("N", "100"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "10"))
TEMPLATE_ID = os.environ.get("TEMPLATE_ID", "")
SOURCE_IMAGE = os.environ.get("SOURCE_IMAGE", "ubuntu:22.04")
PUBLISH = os.environ.get("PUBLISH", "s3://sandbox-images/publish")
WARMUP = int(os.environ.get("WARMUP", "2"))
READY_TIMEOUT_COLD = int(os.environ.get("READY_TIMEOUT_COLD", "900"))
READY_TIMEOUT_WARM = int(os.environ.get("READY_TIMEOUT_WARM", "300"))

CONNECTION_CONFIG = ConnectionConfig(domain=DOMAIN, protocol=PROTOCOL, api_key=API_KEY)


async def ensure_template(manager: SandboxManager) -> str:
    template_id = os.environ.get("TEMPLATE_ID", "")
    if template_id:
        print(f"==> reusing template {template_id}")
        return template_id

    created = await manager.create_template(
        CreateTemplateRequest(
            image=SOURCE_IMAGE,
            publish=PUBLISH,
            format="native",
            resource_limits={"cpu": "1", "memory": "512Mi", "disk": "2Gi"},
            readiness=TemplateReadiness(warmup_seconds=15),
            metadata={"origin": "create-bench"},
        )
    )
    template_id = created.template_id
    print(f"==> templateId: {template_id} — waiting for build")
    while True:
        info = await manager.get_template(template_id)
        phase = info.status.phase
        if phase == TemplatePhase.SUCCEEDED:
            print("==> template build Succeeded")
            return template_id
        if phase == TemplatePhase.FAILED:
            sys.exit(f"ERROR: template {template_id} build Failed: {info.status.message}")
        print(".", end="", flush=True)
        await asyncio.sleep(2)


async def one_create(manager: SandboxManager, template_id: str, ready_timeout: int):
    """Returns (latency_seconds, sandbox_id) or raises on failure."""
    start = time.monotonic()
    sandbox = await Sandbox.create_from_template(
        template_id,
        timeout=timedelta(hours=1),
        ready_timeout=timedelta(seconds=ready_timeout),
        connection_config=CONNECTION_CONFIG,
    )
    latency = time.monotonic() - start
    return latency, sandbox.id


async def main():
    manager = await SandboxManager.create(CONNECTION_CONFIG)
    template_id = await ensure_template(manager)

    # warmup: absorb the first artifact pull on every fastlet node (untimed)
    for i in range(WARMUP):
        t0 = time.monotonic()
        try:
            latency, sandbox_id = await one_create(manager, template_id, READY_TIMEOUT_COLD)
        except Exception as err:
            sys.exit(f"ERROR: warmup {i + 1}/{WARMUP} failed: {err}")
        print(f"==> warmup {i + 1}/{WARMUP}: ready in {time.monotonic() - t0:.2f}s "
              f"(sdk={latency:.2f}s, id={sandbox_id}) — killing")
        await manager.kill_sandbox(sandbox_id)

    print(f"==> measuring {N} creates at CONCURRENCY={CONCURRENCY}")
    semaphore = asyncio.Semaphore(CONCURRENCY)
    samples, failures = [], []

    async def run(i):
        async with semaphore:
            try:
                latency, sandbox_id = await one_create(manager, template_id, READY_TIMEOUT_WARM)
            except Exception as err:
                failures.append(i)
                print(f"[{i}/{N}] FAILED: {err}", flush=True)
                return
            samples.append(latency)
            await manager.kill_sandbox(sandbox_id)
            print(f"[{i}/{N}] create={latency:.3f}s id={sandbox_id} (killed)", flush=True)

    await asyncio.gather(*(run(i) for i in range(1, N + 1)))

    if not samples:
        sys.exit(f"ERROR: all {len(failures)} creates failed")

    def pct(p):
        ordered = sorted(samples)
        return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]

    print(f"\n=== fsb create latency over {len(samples)} runs, {len(failures)} failed "
          f"(seconds, concurrency {CONCURRENCY}) ===")
    print(f"avg = {statistics.mean(samples):.3f}")
    print(f"p50 = {pct(50):.3f}")
    print(f"p90 = {pct(90):.3f}")
    print(f"p99 = {pct(99):.3f}")
    print(f"min = {min(samples):.3f}   max = {max(samples):.3f}")


if __name__ == "__main__":
    asyncio.run(main())
