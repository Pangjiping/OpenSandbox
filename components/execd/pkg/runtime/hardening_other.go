//go:build !linux

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

// Hardening is Linux-only (OSEP-0018); on other platforms it is a no-op.

package runtime

import "github.com/alibaba/opensandbox/execd/pkg/isolation"

// InitHardening is a no-op off Linux.
func InitHardening(cfg isolation.Config) error {
	return nil
}

// SetEbpfState is a no-op off Linux.
func SetEbpfState(state LayerState) {}

// HardeningReport reports that no hardening layer is in effect.
func ReportHardening() HardeningReport {
	initMode, shield := InitModeReport()
	return HardeningReport{
		InitMode:     initMode,
		SignalShield: shield,
		CapDrop:      LayerState{State: "disabled", Message: "hardening is Linux-only"},
		Seccomp:      LayerState{State: "disabled", Message: "hardening is Linux-only"},
		Landlock:     LayerState{State: "disabled", Message: "hardening is Linux-only"},
		Ebpf:         LayerState{State: "disabled", Message: "hardening is Linux-only"},
	}
}
