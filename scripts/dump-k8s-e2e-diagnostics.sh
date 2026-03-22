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

# Dump Kind / cluster state after k8s E2E (CI or local). Best-effort: never exits non-zero.
set -uo pipefail

E2E_NS="${E2E_NS:-opensandbox-e2e}"
SYS_NS="${SYS_NS:-opensandbox-system}"

_log_containers() {
	local ns=$1
	local pod=$2
	local kind=$3
	local label=$4
	local names
	names=$(kubectl get pod "${pod}" -n "${ns}" -o "jsonpath={.spec.${kind}[*].name}" 2>/dev/null) || true
	for c in ${names}; do
		[[ -z "${c}" ]] && continue
		echo ""
		echo ">>> ${label}: ${c}"
		kubectl logs -n "${ns}" "${pod}" -c "${c}" --tail=-1 2>&1 || echo "(logs unavailable)"
	done
}

dump_sandbox_pod_logs() {
	local ns=$1
	echo ""
	echo "================ ${ns}: pod logs (stdout/stderr merged per container) ================"
	if ! kubectl get ns "${ns}" >/dev/null 2>&1; then
		echo "namespace ${ns} not found"
		return 0
	fi
	local pr pod
	while IFS= read -r pr; do
		[[ -z "${pr}" ]] && continue
		pod="${pr#pod/}"
		echo ""
		echo "--------------------------------------------------------------------------------"
		echo "Pod: ${pod} (namespace ${ns})"
		echo "--------------------------------------------------------------------------------"
		_log_containers "${ns}" "${pod}" "initContainers" "initContainer"
		_log_containers "${ns}" "${pod}" "containers" "container"
	done < <(kubectl get pods -n "${ns}" -o name 2>/dev/null || true)
}

dump_sandbox_pod_logs "${E2E_NS}"

kubectl get pods -n "${E2E_NS}" || true
kubectl describe deployment -n "${SYS_NS}" opensandbox-controller-manager || true
kubectl describe deployment -n "${SYS_NS}" opensandbox-server || true
kubectl get svc -n "${SYS_NS}" opensandbox-server || true
