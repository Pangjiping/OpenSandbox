#!/bin/bash

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

# Smoke: an upstream that goes BLACK mid-run (IP vanished behind a silent drop) must not
# fail client queries: the proxy fails over to the next upstream after one exchange
# timeout, and the periodic probe then drops the dead upstream from the active list.
#
# Hermetic: two local DNS responders (tests/blackhole_upstream.py on 127.0.0.2/127.0.0.3)
# play the upstreams, so no public resolver is needed and behavior is identical on any
# runner. An iptables OUTPUT DROP then black-holes the first one mid-run — a silent drop
# that also swallows the proxy's SO_MARKed queries, exactly like a vanished IP behind a
# routing black hole. Unlike smoke-dns-upstream-probe.sh (dead PORT = instant ICMP
# refused), the window dig below MUST burn the full exchange timeout on the dead upstream:
# the 1500-4000ms two-sided bound proves the ejection window was actually exercised
# (a proxy that fails over without the burned timeout, or not at all, fails this test).
#
# Requires Docker with --cap-add=NET_ADMIN.
#
# Example:
#   ./smoke-dns-upstream-blackhole.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

IMG="opensandbox/egress:local"
containerName="egress-smoke-dns-upstream-blackhole"
POLICY_PORT=18080
# Overwritten each run; inspect locally after failure.
EGRESS_LOG_FILE="${SCRIPT_DIR}/egress-smoke-dns-upstream-blackhole.egress.log"

# Local upstreams: distinct loopback IPs, whole 127/8 is local on lo.
UPSTREAM_A="127.0.0.2"
UPSTREAM_A_PORT=5321
UPSTREAM_B="127.0.0.3"
UPSTREAM_B_PORT=5322
# Exchange timeout (sec): the window dig below must take ~this long (one burned
# timeout on the black-holed upstream) plus one cheap local round trip.
UPSTREAM_TIMEOUT="${UPSTREAM_TIMEOUT:-2}"
# Probe interval (sec): 15 keeps the next probe round (and its ejection refresh)
# clear of the window phase while keeping the ejection wait short.
PROBE_INTERVAL="${PROBE_INTERVAL:-15}"

info() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { info "PASS: $*"; }

cleanup() {
  docker rm -f "${containerName}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# dig via the in-container proxy; fail unless NOERROR and min_ms <= Query time < max_ms.
run_dig() {
  local label="$1" min_ms="$2" max_ms="$3" out qt
  out="$(docker exec "${containerName}" dig @127.0.0.1 -p 15353 +tries=1 +time=25 example.com. 2>&1)" || true
  echo "${out}" | tail -n 4
  qt="$(echo "${out}" | sed -n 's/^;; Query time: \([0-9]*\) msec/\1/p' | head -1)"
  if [[ -z "${qt}" ]]; then
    fail "${label}: could not parse dig Query time (dig failed? output above)"
  fi
  if ! grep -q 'status: NOERROR' <<<"${out}"; then
    fail "${label}: expected NOERROR, got: $(grep -m1 -o 'status: [A-Z]*' <<<"${out}" || echo 'no header')"
  fi
  if [[ "${qt}" -lt "${min_ms}" || "${qt}" -ge "${max_ms}" ]]; then
    fail "${label}: query took ${qt} msec (expected ${min_ms}-${max_ms} msec)"
  fi
  info "${label}: NOERROR in ${qt} msec (${min_ms}-${max_ms})"
}

info "Building image ${IMG}"
docker build -t "${IMG}" -f "${REPO_ROOT}/components/egress/Dockerfile" "${REPO_ROOT}"

info "Starting ${containerName} (local upstreams ${UPSTREAM_A}:${UPSTREAM_A_PORT}, ${UPSTREAM_B}:${UPSTREAM_B_PORT}, timeout=${UPSTREAM_TIMEOUT}s, probe=${PROBE_INTERVAL}s)"
docker run -d --name "${containerName}" \
  --cap-add=NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  -e OPENSANDBOX_EGRESS_MODE=dns \
  -e OPENSANDBOX_EGRESS_RULES='{"defaultAction":"allow"}' \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM="${UPSTREAM_A}:${UPSTREAM_A_PORT},${UPSTREAM_B}:${UPSTREAM_B_PORT}" \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM_TIMEOUT="${UPSTREAM_TIMEOUT}" \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM_PROBE_INTERVAL_SEC="${PROBE_INTERVAL}" \
  -e OPENSANDBOX_EGRESS_LOG_LEVEL=info \
  -p "${POLICY_PORT}:18080" \
  "${IMG}"

info "Starting local DNS responders for both upstreams"
docker cp "${SCRIPT_DIR}/blackhole_upstream.py" "${containerName}:/tmp/blackhole_upstream.py"
docker exec -d "${containerName}" python3 /tmp/blackhole_upstream.py "${UPSTREAM_A}" "${UPSTREAM_A_PORT}"
docker exec -d "${containerName}" python3 /tmp/blackhole_upstream.py "${UPSTREAM_B}" "${UPSTREAM_B_PORT}"

info "Waiting for policy server..."
for _ in {1..50}; do
  if curl -sf "http://127.0.0.1:${POLICY_PORT}/healthz" >/dev/null; then
    break
  fi
  sleep 0.5
done

# Let the startup probe round mark both responders healthy.
sleep 3

info "Baseline: both upstreams healthy, first one must answer directly"
run_dig "baseline" 0 1000

info "Black-holing ${UPSTREAM_A} mid-run (silent OUTPUT DROP, SO_MARKed queries included)"
docker exec "${containerName}" iptables -I OUTPUT -d "${UPSTREAM_A}" -j DROP

info "Ejection window: dead upstream still active; failover to ${UPSTREAM_B} must burn ~${UPSTREAM_TIMEOUT}s on it"
run_dig "window-failover" "$((UPSTREAM_TIMEOUT * 1000 - 500))" "$((UPSTREAM_TIMEOUT * 1000 + 2000))"

docker logs "${containerName}" >"${EGRESS_LOG_FILE}" 2>&1
if ! grep -q "upstream ${UPSTREAM_A}:${UPSTREAM_A_PORT} exchange error" "${EGRESS_LOG_FILE}"; then
  fail "expected log line \"upstream ${UPSTREAM_A}:${UPSTREAM_A_PORT} exchange error\" (failover attempt); see ${EGRESS_LOG_FILE}"
fi
pass "log shows exchange error on ${UPSTREAM_A} before failover (saved in ${EGRESS_LOG_FILE})"

waited=$((PROBE_INTERVAL + UPSTREAM_TIMEOUT + 3))
info "Waiting ${waited}s for the probe to eject the black-holed upstream"
sleep "${waited}"

info "After ejection: queries must go straight to ${UPSTREAM_B} (no burned timeout)"
run_dig "after-ejection" 0 1000

docker logs "${containerName}" >"${EGRESS_LOG_FILE}" 2>&1
if ! grep -q "upstream probe ${UPSTREAM_A}:${UPSTREAM_A_PORT} failed" "${EGRESS_LOG_FILE}"; then
  fail "expected log line \"upstream probe ${UPSTREAM_A}:${UPSTREAM_A_PORT} failed\" (ejection); see ${EGRESS_LOG_FILE}"
fi
pass "log shows probe failure and ejection of ${UPSTREAM_A} (saved in ${EGRESS_LOG_FILE})"

info "All smoke tests passed."
