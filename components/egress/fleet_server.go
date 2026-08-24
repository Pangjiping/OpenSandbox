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

// Fleet-profile control plane surface (OSEP-0021): one listener on the Pod
// netns loopback, N subjects. Every policy/credential operation is routed to
// a subject by the X-Fast-Sandbox-Uid header injected by fastlet-proxy (the
// only peer: the listener binds 127.0.0.1 and sandbox netns cannot reach it).
//
// Create-then-configure semantics: a push for a UID whose slot has not been
// observed yet is cached as pending (bounded TTL) and applied when the slot
// appears; the subject is deny-first from observation until then, so the push
// can be late, never early-open. When the push carries the optional
// X-Fast-Sandbox-Generation header, a fencing mismatch drops the pending
// entry instead of applying it (a reset can never carry old policy into a new
// sandbox).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/resolvrewrite"
	"github.com/alibaba/opensandbox/egress/pkg/slotsource"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/alibaba/opensandbox/internal/safego"
)

// subjectHeaderPattern restricts header values to opaque subject IDs.
func validSubjectID(uid string) bool {
	if uid == "" || len(uid) > 128 {
		return false
	}
	for _, r := range uid {
		if r == '/' || r == '\\' || r == 0 {
			return false
		}
	}
	return true
}

// pendingRequest is a cached policy/credential push for a UID whose slot is
// not observed yet.
type pendingRequest struct {
	method   string
	path     string
	body     []byte
	gen      uint64
	hasGen   bool
	deadline time.Time
}

// fleetNftApplier is the per-subject nft surface used by the fleet control plane
// (implemented by fleetnft.Applier; narrowed here for testability).
type fleetNftApplier interface {
	ApplyDenyFirst(ctx context.Context, s subject.Subject, slot slotsource.Slot) error
	ApplyPolicy(ctx context.Context, s subject.Subject, pol *policy.NetworkPolicy) error
	Remove(ctx context.Context, s subject.Subject) error
}

// fleetPolicyServer is the multi-subject control plane. It implements
// subject.LifecycleHooks: OnRegistered installs deny-first enforcement
// (nft + resolv) under the registry lock; OnRegisteredComplete flushes any
// cached pending push for the subject.
type fleetPolicyServer struct {
	ctx        context.Context
	reg        *subject.MemoryRegistry
	nft        fleetNftApplier
	pendingTTL time.Duration

	mu      sync.Mutex
	pending map[subject.Subject]*pendingRequest
	vaults  map[subject.Subject]*credentialvault.Store

	policyMu sync.Mutex // serializes policy applies (registry + nft stay ordered)
}

func newFleetPolicyServer(ctx context.Context, reg *subject.MemoryRegistry, nft fleetNftApplier, pendingTTL time.Duration) *fleetPolicyServer {
	if pendingTTL <= 0 {
		pendingTTL = time.Duration(constants.DefaultPendingPushTTL) * time.Second
	}
	return &fleetPolicyServer{
		ctx:        ctx,
		reg:        reg,
		nft:        nft,
		pendingTTL: pendingTTL,
		pending:    make(map[subject.Subject]*pendingRequest),
		vaults:     make(map[subject.Subject]*credentialvault.Store),
	}
}

// Handler returns the fleet-profile HTTP mux.
func (s *fleetPolicyServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.HandleFunc("/credential-vault", s.handleCredentialVault)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// subjectOf extracts and validates the routing header. The proxy is the only
// peer on the loopback listener; the header is the subject key, not an auth
// credential (the proxy verifies the route credential before forwarding).
func subjectOf(r *http.Request) (subject.Subject, bool) {
	uid := strings.TrimSpace(r.Header.Get(constants.EgressSubjectUIDHeader))
	if !validSubjectID(uid) {
		return "", false
	}
	return subject.FromSandboxUID(uid), true
}

// pendingGeneration reads the optional fencing header on a push.
func pendingGeneration(r *http.Request) (gen uint64, hasGen bool) {
	raw := strings.TrimSpace(r.Header.Get(constants.EgressSubjectGenerationHeader))
	if raw == "" {
		return 0, false
	}
	gen, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return gen, true
}

func (s *fleetPolicyServer) handlePolicy(w http.ResponseWriter, r *http.Request) {
	subj, ok := subjectOf(r)
	if !ok {
		http.Error(w, "missing or invalid "+constants.EgressSubjectUIDHeader, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handlePolicyGet(w, subj)
	case http.MethodPost, http.MethodPut:
		s.handlePolicyReplace(w, r, subj)
	case http.MethodPatch:
		s.handlePolicyPatch(w, r, subj)
	case http.MethodDelete:
		s.handlePolicyDelete(w, r, subj)
	default:
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *fleetPolicyServer) handlePolicyGet(w http.ResponseWriter, subj subject.Subject) {
	user := s.reg.UserPolicy(subj)
	state, ok := s.reg.Get(subj)
	if !ok {
		http.Error(w, "unknown subject", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, policyStatusResponse{
		Status: state.String(),
		Mode:   modeFromPolicy(user),
		Policy: user,
	})
}

// applyPolicy stores the policy in the registry and swaps the subject's nft
// rules. Ordering: registry first, then nft. If the nft swap fails the
// subject stays on its previous (deny-first or older) rules — the fail-closed
// direction; the server retries the push.
//
// The nft swap applies the always-rule MERGED policy (reg.EffectivePolicy),
// not the raw user policy, so allow.always/deny.always are enforced at the
// IP layer too — matching the sidecar profile's commitPolicy behavior. The
// always files are loaded once at startup; runtime file changes are not
// picked up (sidecar reloads them every minute).
func (s *fleetPolicyServer) applyPolicy(r *http.Request, subj subject.Subject, pol *policy.NetworkPolicy) error {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	if err := s.reg.ApplyPolicy(subj, pol); err != nil {
		return err
	}
	// Effective (always-merged) policy is what DNS dispatch and nft both use.
	if eff := s.reg.EffectivePolicy(subj); eff != nil {
		pol = eff
	}
	nftCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	if err := s.nft.ApplyPolicy(nftCtx, subj, pol); err != nil {
		return fmt.Errorf("nft policy apply: %w", err)
	}
	return nil
}

// resolvePolicyPush applies or caches the parsed policy. rawBody is the
// request body as read once by the handler — it is cached verbatim so the
// pending replay applies the EXACT policy the client pushed (the body is
// consumed by parsing, so it must be passed here explicitly).
func (s *fleetPolicyServer) resolvePolicyPush(w http.ResponseWriter, r *http.Request, subj subject.Subject, pol *policy.NetworkPolicy, rawBody string) {
	if _, ok := s.reg.Get(subj); !ok {
		s.cachePending(r, subj, []byte(rawBody))
		writeJSON(w, http.StatusAccepted, policyStatusResponse{
			Status: "pending",
			Reason: "subject not registered yet; push cached",
		})
		return
	}
	if err := s.applyPolicy(r, subj, pol); err != nil {
		logEgressUpdateFailedError(fmt.Sprintf("fleet policy apply (%s): %v", subj, err))
		http.Error(w, fmt.Sprintf("policy apply failed: %v", err), http.StatusInternalServerError)
		return
	}
	logEgressUpdated(pol.DefaultAction, pol.Egress)
	writeJSON(w, http.StatusOK, policyStatusResponse{
		Status:          "ok",
		Mode:            modeFromPolicy(pol),
		EnforcementMode: constants.PolicyDnsNft,
	})
}

func (s *fleetPolicyServer) handlePolicyReplace(w http.ResponseWriter, r *http.Request, subj subject.Subject) {
	raw, err := readPolicyRequestBody(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
		return
	}
	var pol *policy.NetworkPolicy
	if strings.TrimSpace(raw) == "" {
		pol = policy.DefaultDenyPolicy() // empty push = reset to deny-all
	} else {
		pol, err = policy.ParsePolicy(raw)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid policy: %v", err), http.StatusBadRequest)
			return
		}
	}
	s.resolvePolicyPush(w, r, subj, pol, raw)
}

func (s *fleetPolicyServer) handlePolicyPatch(w http.ResponseWriter, r *http.Request, subj subject.Subject) {
	raw, err := readPolicyRequestBody(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
		return
	}
	var patchRules []policy.EgressRule
	if err := json.Unmarshal([]byte(raw), &patchRules); err != nil {
		http.Error(w, fmt.Sprintf("invalid patch rules: %v", err), http.StatusBadRequest)
		return
	}
	if len(patchRules) == 0 {
		http.Error(w, "invalid patch rules: empty array", http.StatusBadRequest)
		return
	}
	newPolicy, err := patchMergedPolicy(s.reg.UserPolicy(subj), patchRules)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid merged policy: %v", err), http.StatusBadRequest)
		return
	}
	s.resolvePolicyPush(w, r, subj, newPolicy, raw)
}

func (s *fleetPolicyServer) handlePolicyDelete(w http.ResponseWriter, r *http.Request, subj subject.Subject) {
	raw, err := readPolicyRequestBody(r)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
		return
	}
	var targets []string
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		http.Error(w, fmt.Sprintf("invalid delete targets: %v", err), http.StatusBadRequest)
		return
	}
	base := s.reg.UserPolicy(subj)
	if base == nil {
		http.Error(w, "unknown subject", http.StatusNotFound)
		return
	}
	newEgress, _ := removeRulesByTarget(base.Egress, targets)
	if len(newEgress) == len(base.Egress) {
		writeJSON(w, http.StatusOK, policyStatusResponse{Status: "ok", Mode: modeFromPolicy(base), Reason: "no matching targets found"})
		return
	}
	newPolicy, err := policy.ParsePolicy(string(mustJSON(policy.NetworkPolicy{DefaultAction: base.DefaultAction, Egress: newEgress})))
	if err != nil {
		http.Error(w, fmt.Sprintf("internal error: %v", err), http.StatusInternalServerError)
		return
	}
	s.resolvePolicyPush(w, r, subj, newPolicy, raw)
}

func (s *fleetPolicyServer) handleCredentialVault(w http.ResponseWriter, r *http.Request) {
	subj, ok := subjectOf(r)
	if !ok {
		http.Error(w, "missing or invalid "+constants.EgressSubjectUIDHeader, http.StatusBadRequest)
		return
	}
	// Read the body once up front so pending caching replays the EXACT
	// pushed revision (ReadJSON below would otherwise consume it).
	var body []byte
	if r.Method != http.MethodGet {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxPolicyBodyBytes))
	}
	if _, ok := s.reg.Get(subj); !ok {
		// Credential pushes ride the same pending path as policy pushes.
		if r.Method == http.MethodGet {
			http.Error(w, "unknown subject", http.StatusNotFound)
			return
		}
		s.cachePending(r, subj, body)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	vault := s.vaultFor(subj)
	switch r.Method {
	case http.MethodGet:
		state, err := vault.Sanitized()
		if err != nil {
			credentialvault.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	case http.MethodPost:
		var req credentialvault.CreateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("invalid credential vault request: %v", err), http.StatusBadRequest)
			return
		}
		state, err := vault.Create(req, s.reg.EffectivePolicy(subj))
		if err != nil {
			credentialvault.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, state)
	case http.MethodPatch:
		var req credentialvault.MutationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("invalid credential vault mutation request: %v", err), http.StatusBadRequest)
			return
		}
		state, err := vault.Patch(req, s.reg.EffectivePolicy(subj))
		if err != nil {
			credentialvault.WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	case http.MethodDelete:
		if err := vault.Delete(); err != nil {
			credentialvault.WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, PATCH, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// vaultFor returns the memory-only per-subject vault, created on first use.
func (s *fleetPolicyServer) vaultFor(subj subject.Subject) *credentialvault.Store {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.vaults[subj]; ok {
		return v
	}
	// Fleet profile: no token/mitm gating; the proxy route is the auth. The
	// vault holds complete revisions memory-only (OSEP-0012 model).
	v := credentialvault.NewStore(nil, func() bool { return true })
	s.vaults[subj] = v
	return v
}

// ---------------------------------------------------------------------------
// Pending cache
// ---------------------------------------------------------------------------

func (s *fleetPolicyServer) cachePending(r *http.Request, subj subject.Subject, body []byte) {
	gen, hasGen := pendingGeneration(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[subj] = &pendingRequest{
		method:   r.Method,
		path:     r.URL.Path,
		body:     body,
		gen:      gen,
		hasGen:   hasGen,
		deadline: time.Now().Add(s.pendingTTL),
	}
}

// OnRegistered implements subject.LifecycleHooks: deny-first enforcement
// (nft rules + resolv.conf rewrite). Runs under the registry write lock, so
// no registry calls here.
func (s *fleetPolicyServer) OnRegistered(subj subject.Subject, slot slotsource.Slot) error {
	nftCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	if err := s.nft.ApplyDenyFirst(nftCtx, subj, slot); err != nil {
		return err
	}
	if err := resolvrewrite.RewriteFile(slot.DNSPath, slot.Gateway); err != nil {
		// Fail closed: a resolv.conf bypassing the proxy would evade DNS
		// policy. The controller retries; the subject stays denying.
		return err
	}
	log.Infof("subject %s deny-first enforced (nft + resolv)", subj)
	return nil
}

// OnRegisteredComplete implements subject.LifecycleHooks: after the registry
// lock is released, flush a cached pending push for the subject. Best effort:
// a failure leaves the subject denying and the server re-pushes (idempotent).
func (s *fleetPolicyServer) OnRegisteredComplete(subj subject.Subject, slot slotsource.Slot) {
	p := s.takePending(subj, slot)
	if p == nil {
		return
	}
	if err := s.replayPending(p, subj); err != nil {
		logEgressUpdateFailedError(fmt.Sprintf("pending push flush for %s failed: %v", subj, err))
	}
}

// takePending atomically removes and returns the pending request if present
// and unexpired. When the push carried a generation header, a mismatch with
// the slot's instance generation drops the entry instead — a delayed push
// from a previous sandbox of the same UID can never carry old policy into a
// new sandbox.
func (s *fleetPolicyServer) takePending(subj subject.Subject, slot slotsource.Slot) *pendingRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[subj]
	if !ok {
		return nil
	}
	delete(s.pending, subj)
	if p.hasGen && p.gen != slot.Owner.InstanceGeneration {
		log.Infof("subject %s: dropped pending push (generation %d != slot generation %d)",
			subj, p.gen, slot.Owner.InstanceGeneration)
		return nil
	}
	if time.Now().After(p.deadline) {
		log.Infof("subject %s: dropped expired pending push (%s %s)", subj, p.method, p.path)
		return nil
	}
	return p
}

// replayPending dispatches a cached push through the normal handler path.
func (s *fleetPolicyServer) replayPending(p *pendingRequest, subj subject.Subject) error {
	r, err := http.NewRequestWithContext(s.ctx, p.method, p.path, strings.NewReader(string(p.body)))
	if err != nil {
		return err
	}
	r.Header.Set(constants.EgressSubjectUIDHeader, strings.TrimPrefix(string(subj), "s-"))
	if p.hasGen {
		r.Header.Set(constants.EgressSubjectGenerationHeader, fmt.Sprintf("%d", p.gen))
	}
	rec := &recordingResponseWriter{header: http.Header{}}
	s.Handler().ServeHTTP(rec, r)
	if rec.status >= 400 {
		return fmt.Errorf("replay %s %s: http %d: %s", p.method, p.path, rec.status, rec.body.String())
	}
	return nil
}

// StartPendingSweep drops expired pending entries in the background.
func (s *fleetPolicyServer) StartPendingSweep(ctx context.Context) {
	safego.Go(func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now()
				s.mu.Lock()
				for subj, p := range s.pending {
					if now.After(p.deadline) {
						delete(s.pending, subj)
					}
				}
				s.mu.Unlock()
			}
		}
	})
}

// OnUnloaded implements subject.LifecycleHooks: remove enforcement and drop
// any cached push (stale for a new sandbox of the same UID).
func (s *fleetPolicyServer) OnUnloaded(subj subject.Subject) error {
	s.mu.Lock()
	delete(s.pending, subj)
	delete(s.vaults, subj)
	s.mu.Unlock()
	nftCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	if err := s.nft.Remove(nftCtx, subj); err != nil {
		return err
	}
	log.Infof("subject %s enforcement removed", subj)
	return nil
}

// recordingResponseWriter captures handler output for pending replays.
type recordingResponseWriter struct {
	header http.Header
	status int
	body   strings.Builder
}

func (w *recordingResponseWriter) Header() http.Header         { return w.header }
func (w *recordingResponseWriter) WriteHeader(status int)      { w.status = status }
func (w *recordingResponseWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
