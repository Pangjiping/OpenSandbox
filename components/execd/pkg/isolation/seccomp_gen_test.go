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

//go:build linux

package isolation

import (
	"testing"

	"github.com/elastic/go-seccomp-bpf/arch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSeccompDenyBPF(t *testing.T) {
	bpf, err := generateSeccompDenyBPF()
	require.NoError(t, err, "BPF generation should succeed on Linux")
	require.NotEmpty(t, bpf, "BPF bytecode should not be empty")

	// Each struct sock_filter entry is 8 bytes.
	assert.True(t, len(bpf) >= 8, "BPF bytecode should contain at least 1 instruction (%d bytes)", len(bpf))
	assert.Equal(t, 0, len(bpf)%8, "BPF bytecode length must be multiple of 8, got %d", len(bpf))

	// First instruction should be a load-absolute at the arch offset (4 bytes),
	// BPF_LD+BPF_W+BPF_ABS = 0x20.
	// Op is little-endian uint16: low byte = 0x20, high byte = 0x00 → 0x0020.
	op := uint16(bpf[0]) | uint16(bpf[1])<<8
	assert.Equal(t, uint16(0x20), op, "first instruction Op should be BPF_LD|BPF_W|BPF_ABS (0x20), got 0x%04x", op)
}

func TestGenerateSeccompDenyBPF_ArchSpecific(t *testing.T) {
	// Verify that all syscalls in denylist resolve on the current arch.
	// generateSeccompDenyBPF filters unknown syscalls, so this should never fail.
	bpf, err := generateSeccompDenyBPF()
	require.NoError(t, err)
	t.Logf("generated %d BPF instructions (%d bytes)", len(bpf)/8, len(bpf))
}

func TestFilterKnownSyscalls(t *testing.T) {
	// Use real arch info to test known vs unknown filtering.
	archInfo, err := arch.GetInfo("")
	require.NoError(t, err)

	names := []string{"open", "read", "nonexistent_syscall_xyz"}
	filtered := filterKnownSyscalls(archInfo, names)
	assert.NotContains(t, filtered, "nonexistent_syscall_xyz", "unknown syscall should be filtered out")
	assert.Contains(t, filtered, "open", "open should be present on all arches")
	assert.Contains(t, filtered, "read", "read should be present on all arches")
}
