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

package fleetnft

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/alibaba/opensandbox/egress/pkg/telemetry"
	"github.com/alibaba/opensandbox/internal/safego"
)

// connectionRefreshInterval is how often active TCP connections renew their
// dynamic set leases (matches the sidecar profile's default).
const connectionRefreshInterval = 30 * time.Second

// conntrackEntry is one Pod-netns conntrack flow in its ORIGINAL direction
// (src = the sandbox's own IP, which REDIRECT preserves).
type conntrackEntry struct {
	src   netip.Addr
	dst   netip.Addr
	state string // TCP state name (e.g. ESTABLISHED)
}

// refreshState is the per-subject lease mirror: which dynamic-set IPs the
// subject currently carries and when they expire, plus the previous tick's
// active set (used for the end-of-activity final refresh).
type refreshState struct {
	dyn  map[netip.Addr]time.Time
	prev map[netip.Addr]struct{}
}

// readConntrack reads the Pod netns conntrack table. The forward hook
// traverses every sandbox flow, so the table holds each sandbox's
// connections keyed by source IP — one read serves all subjects (the OSEP's
// bucketed-per-subject refresh).
func readConntrack(ctx context.Context) ([]conntrackEntry, error) {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		return nil, err
	}
	return parseConntrackTCPEntries(data), nil
}

// parseConntrackTCPEntries parses /proc/net/nf_conntrack lines. Only TCP
// entries with a parseable original-direction src/dst are returned; the
// first src=/dst= tokens on a line are the original direction (the reply
// direction follows for NAT'd flows).
func parseConntrackTCPEntries(data []byte) []conntrackEntry {
	var out []conntrackEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[2] != "tcp" {
			continue
		}
		var e conntrackEntry
		e.state = f[5]
		for _, tok := range f[6:] {
			if v, ok := strings.CutPrefix(tok, "src="); ok && !e.src.IsValid() {
				if a, err := netip.ParseAddr(v); err == nil {
					e.src = a
				}
				continue
			}
			if v, ok := strings.CutPrefix(tok, "dst="); ok && !e.dst.IsValid() {
				if a, err := netip.ParseAddr(v); err == nil {
					e.dst = a
				}
			}
		}
		if e.src.IsValid() && e.dst.IsValid() {
			out = append(out, e)
		}
	}
	return out
}

// activeConntrackTCPState reports whether a conntrack TCP state represents
// an active connection (mirrors the sidecar's activeTCPState; conntrack
// collapses FIN_WAIT1/2 into FIN_WAIT, and TIME_WAIT is deliberately
// excluded — the final refresh covers the reconnect grace period instead).
func activeConntrackTCPState(state string) bool {
	switch state {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "CLOSE_WAIT", "CLOSING", "LAST_ACK":
		return true
	default:
		return false
	}
}

// StartConnectionRefresh keeps each subject's DNS-learned IPs authorized
// while TCP connections to them are active; the set timeout remains as the
// grace period after the connection closes. sandboxMir, when non-nil, is
// invoked per subject with the refreshed IPs so the per-sandbox netns mirror
// (pkg/sandboxnft) carries identical leases.
//
// Renewal is best-effort, per subject: a connection that starts and closes
// between polls is never observed (needs a later DNS lookup), an entry that
// expired before its first observation is restored on the next poll, and an
// nft failure extends the gap (existing connections survive through the
// `ct state established` rule). Renewal is a background goroutine; a
// conntrack read failure clears the previous-activity state and skips the
// tick.
func (a *Applier) StartConnectionRefresh(ctx context.Context, sandboxMir func(context.Context, subject.Subject, []nftables.ResolvedIP) error) {
	a.mu.Lock()
	a.sandboxMir = sandboxMir
	a.mu.Unlock()
	safego.Go(func() {
		ticker := time.NewTicker(connectionRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.refreshTick(ctx)
			}
		}
	})
}

// refreshTick performs one refresh pass: bucket the Pod-netns conntrack table
// by source IP, then per subject renew the leases of active connections and
// issue the end-of-activity final refresh. Runs under the applier lock so a
// concurrent AddResolvedIPs or policy operation can never interleave.
func (a *Applier) refreshTick(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	entries, err := a.conntrack(ctx)
	if err != nil {
		// No trustworthy activity data: drop the previous-activity set so no
		// stale "was active" state keeps leases alive beyond their expiry.
		for _, st := range a.states {
			st.prev = make(map[netip.Addr]struct{})
		}
		log.Warnf("fleetnft: conntrack read failed, skipping refresh: %v", err)
		return
	}

	activeBySubject := a.bucketActive(entries)
	for s, st := range a.states {
		ips := st.plan(activeBySubject[s], a.now())
		if len(ips) == 0 {
			continue
		}
		var b strings.Builder
		writeResolvedIPsFragment(&b, s, ips)
		if _, err := a.run(ctx, b.String()); err != nil {
			telemetry.RecordNftablesUpdateFailed(telemetry.NftOpDynamicAdd)
			log.Warnf("fleetnft: refresh dynamic sets for subject %s failed: %v", s, err)
			continue
		}
		telemetry.RecordNftablesUpdate()
		if a.sandboxMir != nil {
			if err := a.sandboxMir(ctx, s, ips); err != nil {
				log.Warnf("fleetnft: sandbox mirror refresh for subject %s failed: %v", s, err)
			}
		}
	}
}

// bucketActive groups the active conntrack flows by subject, keyed on the
// source IP (the dispatch key; REDIRECT preserves it).
func (a *Applier) bucketActive(entries []conntrackEntry) map[subject.Subject]map[netip.Addr]struct{} {
	out := make(map[subject.Subject]map[netip.Addr]struct{})
	for _, e := range entries {
		if !activeConntrackTCPState(e.state) {
			continue
		}
		src := e.src.Unmap()
		s, ok := a.subjectForSrc(src)
		if !ok {
			continue
		}
		m := out[s]
		if m == nil {
			m = make(map[netip.Addr]struct{})
			out[s] = m
		}
		m[e.dst.Unmap()] = struct{}{}
	}
	return out
}

func (a *Applier) subjectForSrc(src netip.Addr) (subject.Subject, bool) {
	for s, inst := range a.subjects {
		if inst.slot.IP == src {
			return s, true
		}
	}
	return "", false
}

// plan computes the refresh for one subject given its currently active
// remote IPs: renew active leases, drop expired leases that are neither
// active nor ending, and issue one final refresh when activity ends so the
// re-added timeout becomes the bounded reconnect grace period (sidecar
// parity). Mutates the state's dyn/prev mirrors.
func (st *refreshState) plan(active map[netip.Addr]struct{}, now time.Time) []nftables.ResolvedIP {
	if st.dyn == nil {
		st.dyn = make(map[netip.Addr]time.Time)
	}
	if st.prev == nil {
		st.prev = make(map[netip.Addr]struct{})
	}
	for addr, expiresAt := range st.dyn {
		if expiresAt.After(now) {
			continue
		}
		if _, isActive := active[addr]; isActive {
			continue
		}
		if _, wasActive := st.prev[addr]; wasActive {
			continue
		}
		delete(st.dyn, addr)
		delete(st.prev, addr)
	}

	current := make(map[netip.Addr]struct{}, len(active))
	refresh := make(map[netip.Addr]struct{})
	for addr := range active {
		if _, ok := st.dyn[addr]; ok {
			current[addr] = struct{}{}
			refresh[addr] = struct{}{}
		}
	}
	// A final refresh when activity ends: the re-added timeout is the
	// reconnect grace period instead of extending every DNS answer globally.
	for addr := range st.prev {
		if _, stillActive := current[addr]; stillActive {
			continue
		}
		if _, known := st.dyn[addr]; known {
			refresh[addr] = struct{}{}
		}
	}

	ips := make([]nftables.ResolvedIP, 0, len(refresh))
	for addr := range refresh {
		ips = append(ips, nftables.ResolvedIP{Addr: addr, TTL: time.Duration(dynSetTimeoutS) * time.Second})
		st.dyn[addr] = now.Add(time.Duration(dynSetTimeoutS) * time.Second)
	}
	st.prev = current
	return ips
}
