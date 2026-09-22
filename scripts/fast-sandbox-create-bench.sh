#!/usr/bin/env bash
# fast-sandbox create-latency bench.
#
# Creates one fsb template, waits for the golden-image build to succeed, then
# creates N sandboxes from that single template via the lifecycle server HTTP
# API and reports avg/p50/p90 (plus min/max) create latency. Each sandbox is
# deleted right after its create is timed so 100 runs never exceed the pool
# capacity (poolMax x maxSandboxesPerPod).
#
# Env:
#   SERVER_URL    lifecycle server base URL (required, e.g. http://11.x.x.x:8080)
#   API_KEY       server api_key (required; the one from values.yaml configToml)
#   N             number of timed creates (default 100)
#   TIMEOUT       sandbox TTL seconds; template mode requires >= 60 (default 300)
#   SOURCE_IMAGE  source OCI image for the golden-image build
#                 (default ubuntu:22.04; must be pullable by the builder pod)
#   PUBLISH       S3-compatible publish target for built artifacts
#   WARMUP        1 = run one untimed warmup create first (default 1; the first
#                 create after a template build pulls artifacts from the store
#                 and would otherwise dominate p90)
set -euo pipefail

SERVER_URL="${SERVER_URL:?SERVER_URL env is required (lifecycle server base URL)}"
API_KEY="${API_KEY:?API_KEY env is required (server configToml server.api_key)}"
N="${N:-100}"
TIMEOUT="${TIMEOUT:-300}"
SOURCE_IMAGE="${SOURCE_IMAGE:-ubuntu:22.04}"
PUBLISH="${PUBLISH:-s3://taskline-zjk-oss-daily/publish}"
WARMUP="${WARMUP:-1}"

TMPDIR_BENCH=$(mktemp -d)
trap 'rm -rf "$TMPDIR_BENCH"' EXIT

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required for stats"; exit 1; }

resp_field() { # resp_field <file> <key> — print a top-level field from a JSON response
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
template_phase() { # template_phase <file>
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"]["phase"])' "$1"
}

# --- 1. declare the fsb template (async golden-image build) ------------------
echo "==> POST /templates (source image: $SOURCE_IMAGE)"
curl -fsS -H "OPEN-SANDBOX-API-KEY: $API_KEY" -H 'Content-Type: application/json' \
  -X POST "$SERVER_URL/templates" \
  -o "$TMPDIR_BENCH/template.json" \
  -d '{"image": "'"$SOURCE_IMAGE"'", "resourceLimits": {"cpu": "1", "memory": "512Mi", "disk": "2Gi"}, "format": "native", "publish": "'"$PUBLISH"'"}'
TEMPLATE_ID=$(resp_field "$TMPDIR_BENCH/template.json" templateId)
echo "==> templateId: $TEMPLATE_ID — waiting for build (rootfs + snapshot are uploaded to the store)"

# --- 2. poll the build until Succeeded ---------------------------------------
while :; do
  curl -fsS -H "OPEN-SANDBOX-API-KEY: $API_KEY" \
    "$SERVER_URL/templates/$TEMPLATE_ID" -o "$TMPDIR_BENCH/tstatus.json"
  phase=$(template_phase "$TMPDIR_BENCH/tstatus.json")
  case "$phase" in
    Succeeded) echo "==> template build Succeeded"; break ;;
    Failed)    echo "ERROR: template build Failed"; exit 1 ;;
    *)         printf '.'; sleep 10 ;;
  esac
done

create_one() { # create_one <id-out-file> — echoes curl total time on stdout
  curl -fsS -o "$1" -w '%{time_total}' -H "OPEN-SANDBOX-API-KEY: $API_KEY" \
    -H 'Content-Type: application/json' -X POST "$SERVER_URL/sandboxes" \
    -d '{"templateId": "'"$TEMPLATE_ID"'", "timeout": '"$TIMEOUT"'}'
}

delete_one() { # delete_one <sandbox-id>
  curl -fsS -H "OPEN-SANDBOX-API-KEY: $API_KEY" \
    -X DELETE "$SERVER_URL/sandboxes/$1" >/dev/null
}

# --- 3. optional warmup (untimed): first create pulls the artifact set -------
if [[ "$WARMUP" != 0 ]]; then
  echo "==> warmup create (untimed; pulls the artifact set onto the fastlet node)"
  t=$(create_one "$TMPDIR_BENCH/warmup.json")
  sid=$(resp_field "$TMPDIR_BENCH/warmup.json" id)
  echo "==> warmup done (${t}s, id=$sid) — deleting"
  delete_one "$sid"
fi

# --- 4. N timed creates -------------------------------------------------------
RESULTS="$TMPDIR_BENCH/latencies.txt"
: > "$RESULTS"
for i in $(seq 1 "$N"); do
  if ! t=$(create_one "$TMPDIR_BENCH/resp.json"); then
    echo "ERROR: create #$i failed:" >&2
    cat "$TMPDIR_BENCH/resp.json" >&2
    exit 1
  fi
  sid=$(resp_field "$TMPDIR_BENCH/resp.json" id)
  echo "$t" >> "$RESULTS"
  delete_one "$sid"
  echo "[$i/$N] create=${t}s id=$sid (deleted)"
done

# --- 5. stats -----------------------------------------------------------------
python3 - "$RESULTS" <<'EOF'
import sys

xs = sorted(float(line) for line in open(sys.argv[1]) if line.strip())
if not xs:
    sys.exit("no samples")

def pct(p):
    return xs[min(len(xs) - 1, round(p / 100 * (len(xs) - 1)))]

print(f"\n=== fsb create latency over {len(xs)} runs (seconds) ===")
print(f"avg = {sum(xs) / len(xs):.3f}")
print(f"p50 = {pct(50):.3f}")
print(f"p90 = {pct(90):.3f}")
print(f"p99 = {pct(99):.3f}")
print(f"min = {xs[0]:.3f}   max = {xs[-1]:.3f}")
EOF
