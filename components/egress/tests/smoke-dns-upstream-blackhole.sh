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
# Unlike smoke-dns-upstream-probe.sh (dead PORT = instant ICMP refused), this simulates a
# routed black hole: an iptables OUTPUT DROP swallows upstream packets silently — including
# the proxy's SO_MARKed queries — exactly like an IP that disappears mid-flight. The key
# assertion runs while the dead upstream is still in the active list (the "ejection window").
#
# Requires Docker with --cap-add=NET_ADMIN. The container must reach BOTH good resolvers
# over UDP 53. Defaults 8.8.8.8 / 223.5.5.5; override for restricted networks.
#
# Example:
#   ./smoke-dns-upstream-blackhole.sh
#   GOOD_DNS=223.5.5.5 GOOD_DNS2=114.114.114.114 ./smoke-dns-upstream-blackhole.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

IMG="opensandbox/egress:local"
containerName="egress-smoke-dns-upstream-blackhole"
POLICY_PORT=18080
# Overwritten each run; inspect locally after failure.
EGRESS_LOG_FILE="${SCRIPT_DIR}/egress-smoke-dns-upstream-blackhole.egress.log"

GOOD_DNS="${GOOD_DNS:-8.8.8.8}"
GOOD_DNS2="${GOOD_DNS2:-223.5.5.5}"
# Exchange timeout (sec): the window dig below is expected to take ~this long
# (one burned timeout on the black-holed upstream) + one healthy round trip.
UPSTREAM_TIMEOUT="${UPSTREAM_TIMEOUT:-2}"
# Probe interval (sec): ejection wait = this + probe timeout (<=2s).
PROBE_INTERVAL="${PROBE_INTERVAL:-5}"

if [[ "${GOOD_DNS}" == "${GOOD_DNS2}" ]]; then
  echo "GOOD_DNS and GOOD_DNS2 must differ (the upstream list is deduplicated)" >&2
  exit 1
fi

info() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { info "PASS: $*"; }

cleanup() {
  docker rm -f "${containerName}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# dig via the in-container proxy; fail unless NOERROR within max_ms.
run_dig() {
  local label="$1" max_ms="$2" out qt
  out="$(docker exec "${containerName}" dig @127.0.0.1 -p 15353 +tries=1 +time=25 example.com. 2>&1)" || true
  echo "${out}" | tail -n 4
  qt="$(echo "${out}" | sed -n 's/^;; Query time: \([0-9]*\) msec/\1/p' | head -1)"
  if [[ -z "${qt}" ]]; then
    fail "${label}: could not parse dig Query time (dig failed? output above)"
  fi
  if ! grep -q 'status: NOERROR' <<<"${out}"; then
    fail "${label}: expected NOERROR, got: $(grep -m1 -o 'status: [A-Z]*' <<<"${out}" || echo 'no header')"
  fi
  if [[ "${qt}" -ge "${max_ms}" ]]; then
    fail "${label}: query took ${qt} msec (expected < ${max_ms} msec)"
  fi
  info "${label}: NOERROR in ${qt} msec (< ${max_ms})"
}

info "Building image ${IMG}"
docker build -t "${IMG}" -f "${REPO_ROOT}/components/egress/Dockerfile" "${REPO_ROOT}"

info "Starting ${containerName} (upstreams ${GOOD_DNS}:53 then ${GOOD_DNS2}:53, timeout=${UPSTREAM_TIMEOUT}s, probe=${PROBE_INTERVAL}s)"
docker run -d --name "${containerName}" \
  --cap-add=NET_ADMIN \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --sysctl net.ipv6.conf.default.disable_ipv6=1 \
  -e OPENSANDBOX_EGRESS_MODE=dns \
  -e OPENSANDBOX_EGRESS_RULES='{"defaultAction":"allow"}' \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM="${GOOD_DNS}:53,${GOOD_DNS2}:53" \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM_TIMEOUT="${UPSTREAM_TIMEOUT}" \
  -e OPENSANDBOX_EGRESS_DNS_UPSTREAM_PROBE_INTERVAL_SEC="${PROBE_INTERVAL}" \
  -e OPENSANDBOX_EGRESS_LOG_LEVEL=info \
  -p "${POLICY_PORT}:18080" \
  "${IMG}"

info "Waiting for policy server..."
for _ in {1..50}; do
  if curl -sf "http://127.0.0.1:${POLICY_PORT}/healthz" >/dev/null; then
    break
  fi
  sleep 0.5
done

# Let the startup probe round complete with BOTH upstreams healthy.
sleep 3

info "Baseline: both upstreams healthy, first one must answer directly"
run_dig "baseline" 2000

info "Black-holing ${GOOD_DNS} mid-run (silent OUTPUT DROP, SO_MARKed queries included)"
docker exec "${containerName}" iptables -I OUTPUT -d "${GOOD_DNS}" -j DROP

info "Ejection window: dead upstream still active; proxy must fail over to ${GOOD_DNS2} after ~${UPSTREAM_TIMEOUT}s"
run_dig "window-failover" "$((UPSTREAM_TIMEOUT * 1000 + 2000))"

docker logs "${containerName}" >"${EGRESS_LOG_FILE}" 2>&1
if ! grep -q "upstream ${GOOD_DNS}:53 exchange error" "${EGRESS_LOG_FILE}"; then
  fail "expected log line \"upstream ${GOOD_DNS}:53 exchange error\" (failover attempt); see ${EGRESS_LOG_FILE}"
fi
pass "log shows exchange error on ${GOOD_DNS} before failover (saved in ${EGRESS_LOG_FILE})"

waited=$((PROBE_INTERVAL + UPSTREAM_TIMEOUT + 2))
info "Waiting ${waited}s for the probe to eject the black-holed upstream"
sleep "${waited}"

info "After ejection: queries must go straight to ${GOOD_DNS2} (no burned timeout)"
run_dig "after-ejection" 2000

docker logs "${containerName}" >"${EGRESS_LOG_FILE}" 2>&1
if ! grep -q "upstream probe ${GOOD_DNS}:53 failed" "${EGRESS_LOG_FILE}"; then
  fail "expected log line \"upstream probe ${GOOD_DNS}:53 failed\" (ejection); see ${EGRESS_LOG_FILE}"
fi
pass "log shows probe failure and ejection of ${GOOD_DNS} (saved in ${EGRESS_LOG_FILE})"

info "All smoke tests passed."
