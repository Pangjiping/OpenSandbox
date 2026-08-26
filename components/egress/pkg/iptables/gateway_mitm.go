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

// Gateway MITM redirect (fleet profile): the shared mitmdump listens on the
// Pod netns (0.0.0.0:18081, like the shared DNS proxy on :15353 — a
// 127.0.0.1 bind would never receive traffic DNATed to the gateway veth
// address). Per-sandbox interception is one prerouting DNAT rule keyed by the
// sandbox's source IP:
//
//	table inet opensandbox_gateway_mitm
//	  chain gw { type nat hook prerouting priority dstnat; }
//	    ip saddr <sandbox> ip daddr <gateway> tcp dport {80,443} return
//	    ip saddr <sandbox> tcp dport {80,443} dnat to <gateway>:18081
//
// Placement in the POD netns prerouting (not the sandbox netns OUTPUT) is
// deliberate:
//
//   - The sandbox-netns OUTPUT filter (pkg/sandboxnft) and the Pod-netns
//     forward hook still see the REAL destination, so policy matching stays
//     exact with no rule changes; the DNAT runs after both, on the veth.
//   - SO_ORIGINAL_DST on the mitmdump socket (Pod-netns conntrack) yields the
//     true target address, so transparent mode needs no Host/SNI fallback.
//   - The sandbox cannot see or tamper with the rule (it lives in the Pod
//     netns), and the egress's own traffic (source = Pod addresses) never
//     matches the sandbox saddr key — the sidecar's uid-owner exclusion is
//     unnecessary here.
//
// The gateway-dst RETURN keeps sandbox->management-plane traffic (the
// fastlet-proxy / gateway services) out of the proxy, mirroring the sidecar's
// loopback exclusion.
//
// The table is rebuilt wholesale from the in-memory entry list on every
// change; nft batches are transactional, so a failed rebuild leaves the
// previous table intact. A brief gap during a rebuild only means
// "not intercepted" for a few milliseconds — policy enforcement stays on
// (forward hook + sandbox layer see the real destination), and registration
// is fail-closed: the rebuild runs BEFORE the subject is marked registered.
package iptables

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/log"
)

const gatewayMitmNftTable = "opensandbox_gateway_mitm"

// MitmRedirectEntry is one sandbox's interception mapping: HTTP(S) from
// SandboxIP is DNATed to Gateway:port in the Pod netns.
type MitmRedirectEntry struct {
	SandboxIP netip.Addr
	Gateway   netip.Addr
}

// mitmRedirectScript builds the wholesale table rebuild for the given entries.
func mitmRedirectScript(entries []MitmRedirectEntry, port int, dports []int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "delete table inet %s\n", gatewayMitmNftTable)
	fmt.Fprintf(&b, "add table inet %s\n", gatewayMitmNftTable)
	fmt.Fprintf(&b, "add chain inet %s gw { type nat hook prerouting priority dstnat; }\n", gatewayMitmNftTable)
	dportList := mitmDportList(dports)
	for _, e := range entries {
		key := "ip"
		addr := e.SandboxIP.Unmap()
		if addr.Is6() {
			key = "ip6"
		}
		if e.Gateway.IsValid() {
			gwKey := "ip6"
			if e.Gateway.Unmap().Is4() {
				gwKey = "ip"
			}
			fmt.Fprintf(&b, "add rule inet %s gw %s saddr %s %s daddr %s tcp dport %s return\n",
				gatewayMitmNftTable, key, addr, gwKey, e.Gateway.Unmap(), dportList)
		}
		fmt.Fprintf(&b, "add rule inet %s gw %s saddr %s tcp dport %s dnat to %s:%d\n",
			gatewayMitmNftTable, key, addr, dportList, e.Gateway.Unmap(), port)
	}
	return b.String()
}

func mitmDportList(dports []int) string {
	parts := make([]string, 0, len(dports))
	for _, p := range dports {
		parts = append(parts, strconv.Itoa(p))
	}
	if len(parts) == 0 {
		return "80,443"
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// InstallMitmRedirects rebuilds the per-sandbox interception table from the
// authoritative entry list (the fleet server's in-memory subjects). Failures
// are transactional: the previous table stays live. A missing table on first
// install is retried without the delete line.
func InstallMitmRedirects(entries []MitmRedirectEntry, port int, dports []int) error {
	if port <= 0 {
		return fmt.Errorf("mitm redirect: invalid port %d", port)
	}
	r := defaultRedirectRunner()
	script := mitmRedirectScript(entries, port, dports)
	if _, err := r.runNft(context.Background(), script); err != nil {
		if isMitmMissingTableError(err) {
			if _, retryErr := r.runNft(context.Background(), removeMitmDeleteTableLine(script)); retryErr == nil {
				log.Infof("mitm redirect installed after missing-table retry")
				return nil
			}
		}
		return fmt.Errorf("mitm redirect install: %w", err)
	}
	log.Infof("mitm redirect installed (%d subject(s) -> :%d)", len(entries), port)
	return nil
}

// RemoveMitmRedirects removes the whole interception table (idempotent; a
// missing table is not an error).
func RemoveMitmRedirects() error {
	r := defaultRedirectRunner()
	if _, err := r.runNft(context.Background(), fmt.Sprintf("delete table inet %s\n", gatewayMitmNftTable)); err != nil {
		if isMitmMissingTableError(err) {
			return nil
		}
		return fmt.Errorf("mitm redirect remove: %w", err)
	}
	log.Infof("mitm redirect removed")
	return nil
}

func isMitmMissingTableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return (strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist")) &&
		strings.Contains(msg, gatewayMitmNftTable)
}

func removeMitmDeleteTableLine(script string) string {
	lines := strings.Split(script, "\n")
	var filtered []string
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "delete table inet "+gatewayMitmNftTable) {
			continue
		}
		filtered = append(filtered, l)
	}
	return strings.Join(filtered, "\n")
}
