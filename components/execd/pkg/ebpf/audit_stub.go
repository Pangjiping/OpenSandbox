//go:build !ebpf

// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// eBPF observation is compiled only into the execd-ebpf variant (CGO +
// cilium/ebpf). The default static build reports it as not configured.

package ebpf

import "github.com/alibaba/opensandbox/execd/pkg/isolation"

// Init reports that observation is unavailable in this build.
func Init(cfg *isolation.EbpfConfig, sandboxID string) (state, message string) {
	return "disabled",
		"eBPF observation requires the execd-ebpf build variant (CGO + cilium/ebpf); default image unchanged"
}
