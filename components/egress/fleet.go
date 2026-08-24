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

// Fleet-profile assembly (OSEP-0021): a single egress control plane serving N
// sandboxes sharing one host/network domain. Activated by
// OPENSANDBOX_EGRESS_PROFILE=fleet; the sidecar profile is unchanged.
//
// Control flow:
//
//	slot store (file) --(poll/watch)--> subject.Controller --(hooks)-->
//	  fleetPolicyServer: deny-first nft + resolv rewrite, pending-push flush
//	proxy route --(UID header)--> fleetPolicyServer:18080 (loopback)
//	  policy/vault pushes routed per subject
//	DNS: one shared proxy, per-query policy via source IP dispatch
package main

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/fleetnft"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/nftables"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/slotsource"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/alibaba/opensandbox/internal/safego"
)

// runFleetProfile starts the fleet-profile control plane and blocks until ctx is
// canceled or a fatal error occurs.
func runFleetProfile(ctx context.Context) {
	log.Infof("egress profile: fleet (multi-sandbox control plane)")

	slotDir := envOrDefault(constants.EnvSlotStoreDir, constants.DefaultSlotStoreDir)
	pollSec := constants.EnvIntOrDefault(constants.EnvSlotPollInterval, constants.DefaultSlotPollIntervalSeconds)
	src := slotsource.NewFileSource(slotDir, time.Duration(pollSec)*time.Second)
	log.Infof("slot store source: %s (poll %ds)", src.Dir(), pollSec)

	alwaysDeny, alwaysAllow, err := policy.LoadAlwaysRuleFiles()
	if err != nil {
		log.Fatalf("failed to load always allow/deny rule files: %v", err)
	}

	nftMgr := fleetnft.NewApplier(nil)
	// Recovery: wipe stale rules from a previous egress generation BEFORE
	// rescanning, so no dead subject's policy survives into a new sandbox.
	if err := nftMgr.ApplyReset(ctx); err != nil {
		log.Fatalf("fleet nftables reset failed: %v", err)
	}
	log.Infof("fleet nftables table reset (stale rules cleared)")

	reg := subject.NewRegistry(alwaysDeny, alwaysAllow)
	pendingTTL := time.Duration(constants.EnvIntOrDefault(constants.EnvPendingPushTTL, constants.DefaultPendingPushTTL)) * time.Second
	fleetSrv := newFleetPolicyServer(ctx, reg, nftMgr, pendingTTL)
	controller := subject.NewController(reg, fleetSrv)

	// DNS: one shared listener, per-query policy dispatched by source IP.
	// Bound on :53 (all interfaces) so the default config matches the
	// resolv.conf rewrite (sandboxes are pointed at slot.Gateway:53); the
	// per-query policy selector keeps unknown sources fail-closed.
	dnsAddr := ":53"
	proxy, err := dnsproxy.New(nil, dnsAddr, alwaysDeny, alwaysAllow)
	if err != nil {
		log.Fatalf("failed to init dns proxy: %v", err)
	}
	proxy.SetQueryPolicySelector(func(remote netip.Addr) *dnsproxy.QueryPolicy {
		s, ok := reg.Resolve(subject.SubjectKey{SourceIP: remote})
		if !ok {
			// Unknown source: deny (fail closed), never a default policy.
			log.Warnf("[dns] query from unknown source %s denied (fail closed)", remote)
			return nil
		}
		eff := reg.EffectivePolicy(s)
		if eff == nil {
			log.Warnf("[dns] query from subject %s (source %s) denied: no effective policy", s, remote)
			return nil
		}
		return &dnsproxy.QueryPolicy{
			Policy: eff,
			OnResolved: func(domain string, ips []nftables.ResolvedIP) {
				addCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				if err := nftMgr.AddResolvedIPs(addCtx, s, ips); err != nil {
					log.Warnf("[dns] add resolved IPs to fleet nft failed for subject %s domain %q: %v", s, domain, err)
				}
			},
		}
	})
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("failed to start dns proxy: %v", err)
	}
	log.Infof("fleet dns proxy listening on %s", dnsAddr)

	httpAddr := envOrDefault(constants.EnvEgressHTTPAddr, constants.DefaultFleetServerAddr)
	srv := &http.Server{Addr: httpAddr, Handler: fleetSrv.Handler()}
	safego.Go(func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("fleet policy server error: %v", err)
		}
	})
	log.Infof("fleet policy server listening on %s (loopback, UID-header routed)", httpAddr)

	fleetSrv.StartPendingSweep(ctx)
	controllerErr := controller.StartWatch(ctx, src)

	// Block until shutdown or a fatal control-plane failure (slot store
	// unreadable = fail closed: the daemon must exit, not run unenforced).
	select {
	case <-ctx.Done():
	case err := <-controllerErr:
		log.Fatalf("subject controller exited: %v", err)
	}
	log.Infof("received shutdown signal; shutting down fleet profile")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Errorf("fleet policy server shutdown error: %v", err)
	}
	if err := proxy.Shutdown(); err != nil {
		log.Errorf("fleet dns proxy shutdown error: %v", err)
	}
	// Enforcement is intentionally NOT removed: the kernel rules keep denying
	// while the daemon is down (fail closed); the next start wipes them via
	// ApplyReset before rescannining.
	if err := <-controllerErr; err != nil {
		log.Errorf("subject controller error: %v", err)
	}
	log.Infof("fleet profile shutdown complete")
	_ = os.Stderr.Sync()
}
