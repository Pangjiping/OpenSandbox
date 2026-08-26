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

package iptables

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMitmRedirectScriptV4(t *testing.T) {
	script := mitmRedirectScript([]MitmRedirectEntry{
		{SandboxIP: netip.MustParseAddr("10.0.0.5"), Gateway: netip.MustParseAddr("10.0.0.1")},
	}, 18081, []int{80, 443})

	require.Contains(t, script, "delete table inet "+gatewayMitmNftTable)
	require.Contains(t, script, "add table inet "+gatewayMitmNftTable)
	require.Contains(t, script, "add chain inet "+gatewayMitmNftTable+" gw { type nat hook prerouting priority dstnat; }")

	// management-plane exception: sandbox -> gateway must NOT be intercepted
	require.Contains(t, script, "ip saddr 10.0.0.5 ip daddr 10.0.0.1 tcp dport {80,443} return")
	// the interception DNAT targets the gateway veth address, not loopback
	require.Contains(t, script, "ip saddr 10.0.0.5 tcp dport {80,443} dnat to 10.0.0.1:18081")
}

func TestMitmRedirectScriptV6(t *testing.T) {
	script := mitmRedirectScript([]MitmRedirectEntry{
		{SandboxIP: netip.MustParseAddr("fd00::5"), Gateway: netip.MustParseAddr("fd00::1")},
	}, 18081, []int{80, 443})

	require.Contains(t, script, "ip6 saddr fd00::5 ip6 daddr fd00::1 tcp dport {80,443} return")
	require.Contains(t, script, "ip6 saddr fd00::5 tcp dport {80,443} dnat to fd00::1:18081")
}

func TestMitmRedirectScriptExtraPortsAndEmpty(t *testing.T) {
	script := mitmRedirectScript([]MitmRedirectEntry{
		{SandboxIP: netip.MustParseAddr("10.0.0.5"), Gateway: netip.MustParseAddr("10.0.0.1")},
	}, 18081, []int{80, 443, 8080})
	require.Contains(t, script, "tcp dport {80,443,8080} dnat to 10.0.0.1:18081")

	empty := mitmRedirectScript(nil, 18081, []int{80, 443})
	require.Contains(t, empty, "add chain inet "+gatewayMitmNftTable+" gw")
	require.NotContains(t, empty, "dnat to")
	assert.True(t, strings.HasSuffix(empty, "\n"))
}

func TestMitmDportList(t *testing.T) {
	assert.Equal(t, "{80,443}", mitmDportList([]int{80, 443}))
	assert.Equal(t, "{80,443,8080}", mitmDportList([]int{80, 443, 8080}))
	assert.Equal(t, "80,443", mitmDportList(nil), "empty list falls back to the base intercept set")
}

func TestMitmMissingTableDetection(t *testing.T) {
	assert.True(t, isMitmMissingTableError(parseMitmError("delete table inet opensandbox_gateway_mitm: no such file or directory")))
	assert.True(t, isMitmMissingTableError(parseMitmError("delete table inet opensandbox_gateway_mitm: No such file or directory")))
	assert.True(t, isMitmMissingTableError(parseMitmError("table 'inet opensandbox_gateway_mitm' does not exist")))
	assert.False(t, isMitmMissingTableError(parseMitmError("nft: syntax error")))
	assert.False(t, isMitmMissingTableError(parseMitmError("delete table inet other_table: no such file or directory")))
	assert.False(t, isMitmMissingTableError(nil))
}

func TestRemoveMitmDeleteTableLine(t *testing.T) {
	script := "delete table inet opensandbox_gateway_mitm\nadd table inet opensandbox_gateway_mitm\nadd chain inet opensandbox_gateway_mitm gw { type nat hook prerouting priority dstnat; }\n"
	out := removeMitmDeleteTableLine(script)
	assert.NotContains(t, out, "delete table")
	assert.Contains(t, out, "add table")
	assert.Contains(t, out, "add chain")
}

func parseMitmError(msg string) error {
	return &mitmScriptError{msg: msg}
}

type mitmScriptError struct{ msg string }

func (e *mitmScriptError) Error() string { return e.msg }
