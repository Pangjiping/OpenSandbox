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

# E2E benchmark: baseline (no egress) vs dns (pass-through) vs dns+nft (sync dynamic IP write).
# Baseline: plain Ubuntu container, same workload, no sidecar. Then egress dns and dns+nft.
# Metrics: E2E latency (p50, p99), throughput (req/s).
#
# Usage: ./tests/bench-dns-nft.sh
# Requires: Docker, curl in PATH (for policy push). Egress image and baseline image (default ubuntu:22.04) must have curl.
# Domain list: tests/hostname.txt (one domain per line).
# Override baseline image: BASELINE_IMG=ubuntu:22.04 ./tests/bench-dns-nft.sh (Ubuntu needs curl installed).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME_FILE="${SCRIPT_DIR}/hostname.txt"

IMG="opensandbox/egress:local"
BASELINE_IMG="${BASELINE_IMG:-curlimages/curl:latest}"
CONTAINER_NAME="egress-bench-e2e"
POLICY_PORT=18080
ROUNDS=10

# Load benchmark domains from hostname.txt (one domain per line).
if [[ ! -f "${HOSTNAME_FILE}" ]] || [[ ! -s "${HOSTNAME_FILE}" ]]; then
  echo "Error: domain file not found or empty: ${HOSTNAME_FILE}" >&2
  exit 1
fi
BENCH_DOMAINS=()
while IFS= read -r line; do
  line="${line%%#*}"
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"
  [[ -n "$line" ]] && BENCH_DOMAINS+=( "$line" )
done < "${HOSTNAME_FILE}"
NUM_DOMAINS=${#BENCH_DOMAINS[@]}
if [[ "$NUM_DOMAINS" -eq 0 ]]; then
  echo "Error: no domains in ${HOSTNAME_FILE}" >&2
  exit 1
fi
TOTAL_REQUESTS=$((ROUNDS * NUM_DOMAINS))
CURL_TIMEOUT=10
# Max wall time for the benchmark loop (docker exec); avoid hanging forever.
BENCH_EXEC_TIMEOUT=300

info() { echo "[$(date +%H:%M:%S)] $*"; }

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Compute stats from a file with one numeric value per line (e.g. time_total in seconds).
# Output: count avg_s p50_s p99_s
stats() {
  local file="$1"
  if [[ ! -f "$file" ]] || [[ ! -s "$file" ]]; then
    echo "0 0 0 0"
    return
  fi
  sort -n "$file" > "${file}.sorted"
  local n
  n=$(wc -l < "${file}.sorted")
  if [[ "$n" -eq 0 ]]; then
    echo "0 0 0 0"
    return
  fi
  local avg p50 p99
  avg=$(awk '{s+=$1; c++} END { if(c>0) print s/c; else print 0 }' "$file")
  p50=$(awk -v n="$n" 'NR==int(n*0.5+0.5){print $1; exit}' "${file}.sorted")
  p99=$(awk -v n="$n" 'NR==int(n*0.99+0.5){print $1; exit}' "${file}.sorted")
  echo "$n $avg $p50 $p99"
}

# Run workload inside CONTAINER_NAME; /tmp/bench-domains.txt must already exist in container.
# Usage: run_bench_to <outfile> [limit] [rounds] [timeout]
run_bench_to() {
  local outfile="$1"
  local limit="${2:-9999}"
  local rounds="${3:-1}"
  local use_timeout="${4:-}"
  local cmd=(
    docker exec -e BENCH_TIMEOUT="${CURL_TIMEOUT}" -e BENCH_OUTFILE="${outfile}" -e BENCH_LIMIT="${limit}" -e BENCH_ROUNDS="${rounds}" \
      "${CONTAINER_NAME}" sh -c '
    : > "$BENCH_OUTFILE"
    r=1
    while [ "$r" -le "$BENCH_ROUNDS" ]; do
      n=0
      while IFS= read -r url && [ "$n" -lt "$BENCH_LIMIT" ]; do
        ( curl -o /dev/null -s -I -w "%{time_namelookup}\t%{time_total}\n" --max-time "$BENCH_TIMEOUT" "$url" >> "$BENCH_OUTFILE" ) &
        n=$((n+1))
      done < /tmp/bench-domains.txt
      wait
      r=$((r+1))
    done
    '
  )
  if [[ "$use_timeout" == "timeout" ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${BENCH_EXEC_TIMEOUT}" "${cmd[@]}"
  else
    "${cmd[@]}"
  fi
}

# Copy URL file into container (create temp file, docker cp, rm). Uses BENCH_DOMAINS.
copy_url_file_to_container() {
  local url_file="/tmp/bench-e2e-domains-$$.txt"
  : > "${url_file}"
  for d in "${BENCH_DOMAINS[@]}"; do
    echo "https://${d}" >> "${url_file}"
  done
  docker cp "${url_file}" "${CONTAINER_NAME}:/tmp/bench-domains.txt"
  rm -f "${url_file}"
}

# Run warm-up + timed benchmark, collect timings. Writes /tmp/bench-e2e-{mode}-total.txt, -namelookup.txt, -wall.txt.
# Requires: CONTAINER_NAME running, /tmp/bench-domains.txt inside container.
run_workload() {
  local mode="$1"
  local out_total="/tmp/bench-e2e-${mode}-total.txt"
  local out_namelookup="/tmp/bench-e2e-${mode}-namelookup.txt"
  : > "$out_total"
  : > "$out_namelookup"

  local first_url="https://${BENCH_DOMAINS[0]}"
  sleep 1
  # HEAD request: no response body, only check DNS + TCP + TLS + HTTP response.
  if ! docker exec "${CONTAINER_NAME}" curl -o /dev/null -s -I --max-time "${CURL_TIMEOUT}" "${first_url}"; then
    info "Warm-up curl failed; stderr from one attempt:"
    docker exec "${CONTAINER_NAME}" curl -o /dev/null -s -I --max-time 5 "${first_url}" 2>&1 || true
    return 1
  fi

  info "Warm-up: first 10 domains, 1 round..."
  bench_ret=0
  run_bench_to /tmp/bench-warmup.txt 10 1 2>/tmp/bench-e2e-stderr.txt || bench_ret=$?
  if [[ "$bench_ret" -ne 0 ]]; then
    info "Warm-up run failed (exit $bench_ret); continuing with timed run anyway."
  fi

  info "Running ${TOTAL_REQUESTS} E2E requests (${ROUNDS} rounds × ${NUM_DOMAINS} domains) inside container (max ${BENCH_EXEC_TIMEOUT}s)..."
  local start_ts
  start_ts=$(date +%s.%N)
  bench_ret=0
  run_bench_to /tmp/bench-raw.txt 9999 "${ROUNDS}" timeout 2>/tmp/bench-e2e-stderr.txt || bench_ret=$?
  if [[ "$bench_ret" -ne 0 ]]; then
    info "Benchmark run failed (exit $bench_ret) or hit timeout; using partial results if any."
  fi
  docker cp "${CONTAINER_NAME}:/tmp/bench-raw.txt" /tmp/bench-e2e-raw.txt 2>/dev/null || true
  local end_ts
  end_ts=$(date +%s.%N)

  if [[ -s /tmp/bench-e2e-stderr.txt ]]; then
    info "docker exec stderr (first 10 lines):"
    head -10 /tmp/bench-e2e-stderr.txt >&2
  fi
  if [[ ! -f /tmp/bench-e2e-raw.txt ]]; then
    : > /tmp/bench-e2e-raw.txt
  fi
  local lines
  lines=$(wc -l < /tmp/bench-e2e-raw.txt 2>/dev/null || echo 0)
  if [[ "$lines" -lt $((TOTAL_REQUESTS / 2)) ]]; then
    info "WARN: only ${lines}/${TOTAL_REQUESTS} responses captured; curl may be failing inside container."
  fi

  awk -F'\t' '{print $2}' /tmp/bench-e2e-raw.txt 2>/dev/null > "$out_total"
  awk -F'\t' '{print $1}' /tmp/bench-e2e-raw.txt 2>/dev/null > "$out_namelookup"
  local wall_s
  wall_s=$(awk -v s="$start_ts" -v e="$end_ts" 'BEGIN { print e - s }')
  echo "$wall_s" > "/tmp/bench-e2e-${mode}-wall.txt"
}

# Run one benchmark phase: start sidecar with given mode, push policy, run client workload, collect timings.
# Usage: run_phase "dns" | "dns+nft"
run_phase() {
  local mode="$1"
  info "Phase: ${mode}"
  cleanup
  docker run -d --name "${CONTAINER_NAME}" \
    --cap-add=NET_ADMIN \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --sysctl net.ipv6.conf.default.disable_ipv6=1 \
    -e OPENSANDBOX_EGRESS_MODE="${mode}" \
    -p "${POLICY_PORT}:18080" \
    "${IMG}"

  for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:${POLICY_PORT}/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done

  local policy_egress=""
  for d in "${BENCH_DOMAINS[@]}"; do
    policy_egress="${policy_egress}{\"action\":\"allow\",\"target\":\"${d}\"},"
  done
  policy_egress="${policy_egress%,}"
  local policy_json="{\"defaultAction\":\"deny\",\"egress\":[${policy_egress}]}"
  curl -sf -XPOST "http://127.0.0.1:${POLICY_PORT}/policy" -d "${policy_json}" >/dev/null

  copy_url_file_to_container
  run_workload "${mode}"
}

# Run baseline phase: plain Ubuntu container, no egress sidecar. Same workload for comparison.
run_phase_baseline() {
  info "Phase: baseline (no egress)"
  cleanup
  docker run -d --name "${CONTAINER_NAME}" "${BASELINE_IMG}" sleep 3600
  sleep 2
  copy_url_file_to_container
  run_workload "baseline"
}

# Print comparison table (baseline, dns, dns+nft)
report() {
  local nb n1 n2 avg0 avg1 avg2 p50_0 p50_1 p50_2 p99_0 p99_1 p99_2 wall0 wall1 wall2
  read -r nb avg0 p50_0 p99_0 <<< "$(stats /tmp/bench-e2e-baseline-total.txt)"
  read -r n1 avg1 p50_1 p99_1 <<< "$(stats /tmp/bench-e2e-dns-total.txt)"
  read -r n2 avg2 p50_2 p99_2 <<< "$(stats /tmp/bench-e2e-dns+nft-total.txt)"
  wall0=$(cat /tmp/bench-e2e-baseline-wall.txt 2>/dev/null || echo "0")
  wall1=$(cat /tmp/bench-e2e-dns-wall.txt 2>/dev/null || echo "0")
  wall2=$(cat /tmp/bench-e2e-dns+nft-wall.txt 2>/dev/null || echo "0")
  if [[ "${nb:-0}" -eq 0 ]] || [[ "${n1:-0}" -eq 0 ]] || [[ "${n2:-0}" -eq 0 ]]; then
    echo "WARN: some phases had no successful requests; check sidecar logs and network."
  fi

  local rps0 rps1 rps2
  rps0=$(awk -v n="$nb" -v w="$wall0" 'BEGIN { print (w>0 && n>0) ? n/w : 0 }')
  rps1=$(awk -v n="$n1" -v w="$wall1" 'BEGIN { print (w>0 && n>0) ? n/w : 0 }')
  rps2=$(awk -v n="$n2" -v w="$wall2" 'BEGIN { print (w>0 && n>0) ? n/w : 0 }')

  echo ""
  echo "========== E2E benchmark: baseline vs dns vs dns+nft =========="
  echo "Workload: ${TOTAL_REQUESTS} requests (${ROUNDS} rounds × ${NUM_DOMAINS} domains)"
  echo ""
  printf "%-12s %12s %12s %12s %12s\n" "Mode" "Req/s" "Avg(s)" "P50(s)" "P99(s)"
  printf "%-12s %12s %12.3f %12.3f %12.3f\n" "baseline" "$rps0" "$avg0" "$p50_0" "$p99_0"
  printf "%-12s %12s %12.3f %12.3f %12.3f\n" "dns"      "$rps1" "$avg1" "$p50_1" "$p99_1"
  printf "%-12s %12s %12.3f %12.3f %12.3f\n" "dns+nft"  "$rps2" "$avg2" "$p50_2" "$p99_2"
  echo ""
  echo "baseline: Plain container (${BASELINE_IMG}), no egress sidecar."
  echo "dns:      DNS proxy only, no nft write (pass-through)."
  echo "dns+nft:  DNS proxy + sync AddResolvedIPs before each DNS reply (L2 enforcement)."
  echo ""
  echo "Note: Warm-up runs before each phase. Baseline gives no-proxy comparison."
  echo "=========="
}

info "Building image ${IMG}"
docker build -t "${IMG}" .

run_phase_baseline
run_phase "dns+nft"
run_phase "dns"
report
info "Cleaning up"
cleanup
