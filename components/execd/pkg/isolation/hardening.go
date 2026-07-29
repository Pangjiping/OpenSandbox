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

package isolation

// HardeningLayerState describes the current enforcement state of a hardening
// layer. Every layer is best-effort and fail-open: a layer that cannot be
// applied reports degraded or unsupported rather than aborting startup.
type HardeningLayerState string

const (
	HardeningActive      HardeningLayerState = "active"
	HardeningDisabled    HardeningLayerState = "disabled"
	HardeningDegraded    HardeningLayerState = "degraded"
	HardeningUnsupported HardeningLayerState = "unsupported"
)

// HardeningLayer reports the enforcement state and diagnostic message for a
// single hardening layer. Message is populated when state is not active.
type HardeningLayer struct {
	State   HardeningLayerState `json:"state"`
	Message string              `json:"message,omitempty"`
}

// HardeningProbe reports the result of startup hardening capability probing.
// Returned on the capabilities endpoint so callers see what is actually
// enforced. Every layer reports the best-effort state; a missing prerequisite
// degrades that layer and includes a diagnostic message.
type HardeningProbe struct {
	InitMode     string         `json:"init_mode"`     // "pid1" | "subreaper" | "none"
	SignalShield bool           `json:"signal_shield"` // kernel PID 1 signal shield active
	CapDrop      HardeningLayer `json:"cap_drop"`
	Seccomp      HardeningLayer `json:"seccomp"`
	Landlock     HardeningLayer `json:"landlock"`
	Ebpf         HardeningLayer `json:"ebpf"`
}

// NewHardeningProbe returns a probe with every layer disabled (the default
// state when no hardening is configured or the feature is off).
func NewHardeningProbe() HardeningProbe {
	return HardeningProbe{
		InitMode:     "none",
		SignalShield: false,
		CapDrop:      HardeningLayer{State: HardeningDisabled},
		Seccomp:      HardeningLayer{State: HardeningDisabled},
		Landlock:     HardeningLayer{State: HardeningDisabled},
		Ebpf:         HardeningLayer{State: HardeningDisabled},
	}
}
