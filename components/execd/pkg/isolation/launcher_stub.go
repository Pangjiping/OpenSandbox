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

//go:build !linux

package isolation

import (
	"errors"
	"os/exec"
)

// ErrHardeningDisabled is returned by LaunchWithHardening on non-Linux
// platforms (hardening is Linux-only).
var ErrHardeningDisabled = errors.New("hardening: disabled")

// InitLauncher is a no-op on non-Linux platforms.
func InitLauncher(cfg Config) error { return nil }

// HardeningEnabled always returns false on non-Linux.
func HardeningEnabled() bool { return false }

// LaunchWithHardening returns ErrHardeningDisabled on non-Linux.
func LaunchWithHardening(args []string) (*exec.Cmd, error) { return nil, ErrHardeningDisabled }
