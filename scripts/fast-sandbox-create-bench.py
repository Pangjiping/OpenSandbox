#!/usr/bin/env python3
"""fast-sandbox create-latency bench (execd /ping delivery criterion).

Declares one fsb template, waits for the golden-image build, then creates N
sandboxes via the lifecycle server HTTP API. Mirrors the upstream
verify_one_sandbox flow: a sample is delivered only when guest execd /ping
returns 200 through the signed gateway route (OpenSandbox-Ingress-To header),
polled at short intervals; the sample latency is POST start -> first /ping 200.
Each sandbox is deleted right after delivery; in-flight is bounded by
CONCURRENCY (keep it within poolMax x maxSandboxesPerPod).
Reports avg/p50/p90/p99/min/max for both the POST accept leg and the full
create->ping200 leg.

Env:
  SERVER_URL    lifecycle server base URL (required)
  API_KEY       server api_key (required)
  N             number of timed creates (default 100)
  CONCURRENCY   parallel creates (default 15)
  TIMEOUT       sandbox TTL seconds; template mode requires >= 60 (default 300)
  TEMPLATE_ID   reuse an existing Succeeded template and skip the build
  SOURCE_IMAGE  source OCI image for the golden-image build (default ubuntu:22.04)
  PUBLISH       S3-compatible publish target
  WARMUP        untimed create/delete count before measuring (default 2)
  POLL_INTERVAL seconds between delivery polls (default 0.05)
  POLL_TIMEOUT  give up waiting for /ping 200 after this many seconds (default 120)
  EXECD_PORT    guest execd port exposed through the gateway (default 44772)
"""

import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SERVER_URL = os.environ["SERVER_URL"].rstrip("/")
API_KEY = os.environ["API_KEY"]
N = int(os.environ.get("N", "100"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "15"))
TIMEOUT = int(os.environ.get("TIMEOUT", "300"))
TEMPLATE_ID = os.environ.get("TEMPLATE_ID", "")
SOURCE_IMAGE = os.environ.get("SOURCE_IMAGE", "ubuntu:22.04")
PUBLISH = os.environ.get("PUBLISH", "s3://taskline-zjk-oss-daily/publish")
WARMUP = int(os.environ.get("WARMUP", "2"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "0.05"))
POLL_TIMEOUT = float(os.environ.get("POLL_TIMEOUT", "120"))
EXECD_PORT = os.environ.get("EXECD_PORT", "44772")

HEADERS = {"OPEN-SANDBOX-API-KEY": API_KEY, "Content-Type": "application/json"}


def http(method, path, body=None):
    req = urllib.request.Request(
        SERVER_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=HEADERS,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            if not body:
                return None        # e.g. DELETE 204 No Content
            return json.loads(body)
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace")[:500]
        raise RuntimeError(f"{method} {path} -> HTTP {err.code}: {detail}") from err


def gateway_ping(route, endpoint_url):
    """GET {endpoint}/ping with the routing headers; 200 = delivered."""
    req = urllib.request.Request(endpoint_url + "/ping", headers=route or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def wait_delivered(sandbox_id):
    """Poll until execd /ping returns 200 via the server-issued endpoint."""
    deadline = time.monotonic() + POLL_TIMEOUT
    while time.monotonic() < deadline:
        try:
            endpoint = http("GET", f"/sandboxes/{sandbox_id}/endpoints/{EXECD_PORT}")
            url = endpoint.get("endpoint")
            if url and gateway_ping(endpoint.get("headers"), url):
                return True
        except RuntimeError:
            pass
        time.sleep(POLL_INTERVAL)
    return False


def bench_one(template_id):
    """POST -> poll execd /ping 200 -> DELETE. Returns (total_s, post_s) or
    (None, None) when the sandbox never delivered."""
    start = time.monotonic()
    sandbox_id = http("POST", "/sandboxes", {"templateId": template_id, "timeout": TIMEOUT})["id"]
    post_done = time.monotonic()
    delivered = wait_delivered(sandbox_id)
    total = time.monotonic() - start
    try:
        http("DELETE", f"/sandboxes/{sandbox_id}")
    except Exception as cleanup_err:
        print(f"WARN: delete {sandbox_id} failed: {cleanup_err}", file=sys.stderr)
    return (total, post_done - start) if delivered else (None, None)


def stats(values):
    def pct(p):
        return values[min(len(values) - 1, round(p / 100 * (len(values) - 1)))]
    return (f"avg = {statistics.mean(values):.3f}  p50 = {pct(50):.3f}  "
            f"p90 = {pct(90):.3f}  p99 = {pct(99):.3f}  "
            f"min = {values[0]:.3f}  max = {values[-1]:.3f}")


def main():
    if not TEMPLATE_ID:
        print(f"==> POST /templates (source image: {SOURCE_IMAGE})")
        resp = http("POST", "/templates", {
            "image": SOURCE_IMAGE,
            "resourceLimits": {"cpu": "1", "memory": "512Mi", "disk": "2Gi"},
            "format": "native",
            "publish": PUBLISH,
        })
        template_id = resp["templateId"]
        print(f"==> templateId: {template_id} — waiting for build")
        while True:
            phase = http("GET", f"/templates/{template_id}")["status"]["phase"]
            if phase == "Succeeded":
                print(f"==> template build Succeeded")
                break
            if phase == "Failed":
                sys.exit(f"ERROR: template {template_id} build Failed")
            print(".", end="", flush=True)
            time.sleep(10)
    else:
        template_id = TEMPLATE_ID
        print(f"==> reusing template {template_id}")

    # warmup: absorb the first artifact pull on every fastlet node (untimed)
    for i in range(WARMUP):
        t0 = time.monotonic()
        sandbox_id = http("POST", "/sandboxes", {"templateId": template_id, "timeout": TIMEOUT})["id"]
        ok = wait_delivered(sandbox_id)
        print(f"==> warmup {i + 1}/{WARMUP}: {'delivered' if ok else 'FAILED'} "
              f"in {time.monotonic() - t0:.2f}s — deleting")
        try:
            http("DELETE", f"/sandboxes/{sandbox_id}")
        except Exception as cleanup_err:
            print(f"WARN: delete {sandbox_id} failed: {cleanup_err}", file=sys.stderr)
        if not ok:
            sys.exit("ERROR: warmup sandbox never delivered; check fastlet/pool state")

    print(f"==> measuring {N} creates at CONCURRENCY={CONCURRENCY} "
          f"(delivery = execd /ping 200 via the server-issued endpoint)")
    totals, posts, failures = [], [], []

    def run(i):
        total, post = bench_one(template_id)
        if total is None:
            failures.append(i)
            print(f"[{i}/{N}] FAILED", flush=True)
        else:
            totals.append(total)
            posts.append(post)
            print(f"[{i}/{N}] total={total:.3f}s (post={post:.3f}s)", flush=True)
        return total

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        list(pool.map(run, range(1, N + 1)))

    if not totals:
        sys.exit(f"ERROR: all {len(failures)} creates failed to deliver")

    print(f"\n=== create -> execd /ping 200, {len(totals)} delivered / "
          f"{len(failures)} failed (seconds, concurrency {CONCURRENCY}) ===")
    print("total: " + stats(totals))
    print("post : " + stats(posts))


if __name__ == "__main__":
    main()
