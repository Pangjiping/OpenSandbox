#!/usr/bin/env bash
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

set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${BENCH_DIR}/../.." && pwd)"

# Gradle 9 requires JVM 17+. Override JAVA_HOME when it is unset or points at
# an older JDK; otherwise pick the highest installed major >= 17.
NEEDS_OVERRIDE=false
if [ -z "${JAVA_HOME:-}" ]; then
  NEEDS_OVERRIDE=true
elif [ -x "${JAVA_HOME}/bin/java" ]; then
  MAJOR="$("${JAVA_HOME}/bin/java" -version 2>&1 | sed -nE 's/.*version "([0-9]+).*/\1/p' | head -1)"
  case "${MAJOR}" in
    8|9|10|11|12|13|14|15|16) NEEDS_OVERRIDE=true ;;
  esac
fi
if [ "${NEEDS_OVERRIDE}" = "true" ] && command -v /usr/libexec/java_home > /dev/null 2>&1; then
  # Highest installed major >= 17, e.g. "17.0.7" or "21.0.4".
  VERSION="$(
    /usr/libexec/java_home -V 2>&1 \
      | sed -nE 's/^[[:space:]]*([0-9]+)\.([0-9]+).*/\1.\2/p' \
      | awk -F. '$1 >= 17' \
      | sort -t. -k1,1n -k2,2n | tail -1
  )"
  if [ -n "${VERSION}" ]; then
    JH="$(/usr/libexec/java_home -v "${VERSION}" 2>/dev/null || true)"
    if [ -n "${JH}" ]; then
      export JAVA_HOME="${JH}"
    fi
  fi
fi

LIFECYCLE_ADDR="${LIFECYCLE_ADDR:-127.0.0.1:18080}"
EXECD_ADDR="${EXECD_ADDR:-127.0.0.1:18081}"
MOCK_CONFIG="${MOCK_CONFIG:-${BENCH_DIR}/configs/default.json}"
MOCK_PID=""

cleanup() {
  if [ -n "${MOCK_PID}" ]; then
    kill "${MOCK_PID}" 2>/dev/null || true
    wait "${MOCK_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: run.sh [--mock-config <path>] [-- <driver args...>]

Environment:
  LIFECYCLE_ADDR  lifecycle mock listen address (default 127.0.0.1:18080)
  EXECD_ADDR      execd mock listen address (default 127.0.0.1:18081)
  MOCK_CONFIG     mock server config JSON (default configs/default.json)

Driver args (after --) are forwarded to the benchmark driver, e.g.:
  ./run.sh -- --max-idle 50 --scenarios warm-latency,steady-state
EOF
}

# parse flags
DRIVER_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --mock-config) shift; MOCK_CONFIG="$1" ;;
    --) shift; DRIVER_ARGS=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) DRIVER_ARGS=("$@"); break ;;
  esac
  shift
done

# 1. build the mock server
echo "== building mock server =="
(cd "${BENCH_DIR}/mockserver" && go build -o "${BENCH_DIR}/bin/mockserver" .)

# 2. one run directory holds every artifact of this run (reports, CSVs,
#    mock config, driver args, mock log) for convenient offline analysis.
RUN_DIR="${BENCH_DIR}/results/run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${RUN_DIR}"
printf '%s\n' "${DRIVER_ARGS[@]}" > "${RUN_DIR}/driver-args.txt"
cp "${MOCK_CONFIG}" "${RUN_DIR}/mock-config.json"

# 3. start the mock server
echo "== starting mock server (lifecycle=${LIFECYCLE_ADDR}, execd=${EXECD_ADDR}, config=${MOCK_CONFIG}) =="
echo "== run directory: ${RUN_DIR} =="
"${BENCH_DIR}/bin/mockserver" \
  -lifecycle-addr "${LIFECYCLE_ADDR}" \
  -execd-addr "${EXECD_ADDR}" \
  -config "${MOCK_CONFIG}" \
  > "${RUN_DIR}/mockserver.log" 2>&1 &
MOCK_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "http://${LIFECYCLE_ADDR}/__stats" > /dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
if ! curl -fsS "http://${LIFECYCLE_ADDR}/__stats" > /dev/null 2>&1; then
  echo "error: mock server did not come up" >&2
  cat "${RUN_DIR}/mockserver.log" >&2
  exit 1
fi

# 4. run the driver (Kotlin SDK is built from source via composite build,
#    see kotlin/settings.gradle.kts)
echo "== running benchmark driver =="
DRIVER_ARGS+=("--report-dir" "${RUN_DIR}")
# Forward the effective mock address unless the user pinned --mock-base-url.
case " ${DRIVER_ARGS[*]} " in
  *" --mock-base-url "*) ;;
  *) DRIVER_ARGS+=("--mock-base-url" "http://${LIFECYCLE_ADDR}") ;;
esac
(cd "${BENCH_DIR}/kotlin" && ./gradlew --console=plain run --args="${DRIVER_ARGS[*]}")

echo "== done: ${RUN_DIR} =="
