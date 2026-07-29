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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLaunchChild_CmdEncoding(t *testing.T) {
	policy := HardeningPolicy{
		KeepCaps:  nil,
		TargetUID: 1000,
		TargetGID: 1000,
	}
	cmd, err := LaunchChild("/tmp/fake-launcher", []string{"/bin/echo", "hello"}, policy, nil)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/fake-launcher", cmd.Path)

	// Find the -- separator and verify the command args follow it.
	args := cmd.Args
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	require.GreaterOrEqual(t, sepIdx, 0)
	userArgs := args[sepIdx+1:]
	assert.Equal(t, []string{"/bin/echo", "hello"}, userArgs)
}

func TestLaunchChild_PolicyEncoded(t *testing.T) {
	policy := HardeningPolicy{
		KeepCaps:  []string{"CAP_NET_BIND_SERVICE"},
		TargetUID: 65534,
		TargetGID: 65534,
	}
	cmd, err := LaunchChild("/tmp/fake-launcher", []string{"/bin/sh"}, policy, []byte{0x00, 0x01})
	require.NoError(t, err)

	// Policy and seccomp should be base64-encoded in args, not plain text.
	foundPolicy := false
	foundSeccomp := false
	for i, a := range cmd.Args {
		if a == "--policy" && i+1 < len(cmd.Args) {
			assert.NotEmpty(t, cmd.Args[i+1])
			assert.NotContains(t, cmd.Args[i+1], "CAP_NET_BIND_SERVICE") // base64, not plain
			foundPolicy = true
		}
		if a == "--seccomp" && i+1 < len(cmd.Args) {
			assert.NotEmpty(t, cmd.Args[i+1])
			assert.NotEqual(t, "none", cmd.Args[i+1])
			foundSeccomp = true
		}
	}
	assert.True(t, foundPolicy)
	assert.True(t, foundSeccomp)
}
