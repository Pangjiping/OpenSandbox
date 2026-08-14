/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MockServer implements the OpenSandbox lifecycle API surface used by the
// sandbox SDKs plus a per-sandbox execd listener. It is a standalone,
// language-agnostic mock intended for pool benchmarks: it simulates
// provisioning latency, sandbox boot time, server-side TTL expiry, and
// per-endpoint faults.
type MockServer struct {
	cfgMu     sync.RWMutex
	cfg       *Config
	mu        sync.RWMutex
	nextSeq   uint64
	sandboxes map[string]*Sandbox

	execdHost string
	execdPort int

	stats Stats
	qps   *QpsRegistry
	alive *gaugeTracker
}

// Sandbox is the mock's view of a sandbox on the lifecycle side.
type Sandbox struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	State     string // "Pending" | "Running" | "Terminated"
	Poisoned  bool
}

func (s *Sandbox) alive(now time.Time) bool {
	return s.State != "Terminated" && (s.ExpiresAt.IsZero() || s.ExpiresAt.After(now))
}

func (s *Sandbox) running(now time.Time) bool {
	return s.alive(now) && s.State == "Running"
}

func newMockServer(cfg *Config, execdHost string, execdPort int, windowSec int) *MockServer {
	return &MockServer{
		cfg:       cfg,
		sandboxes: make(map[string]*Sandbox),
		execdHost: execdHost,
		execdPort: execdPort,
		qps:       newQpsRegistry(windowSec),
		alive:     newGaugeTracker(windowSec),
	}
}

// startAliveTicker records the alive-sandbox count once per second so the
// driver can see the pool-size trajectory (over-creation, shrink, drift).
func (m *MockServer) startAliveTicker() {
	record := func(now time.Time) {
		m.mu.RLock()
		alive := 0
		for _, sb := range m.sandboxes {
			if sb.alive(now) {
				alive++
			}
		}
		m.mu.RUnlock()
		m.alive.record(now, int64(alive))
	}
	record(time.Now())
	ticker := time.NewTicker(time.Second)
	for range ticker.C {
		record(time.Now())
	}
}

// recordQps attributes one request to a route. Handlers defer this at entry so
// every outcome (including faults) is counted.
func (m *MockServer) recordQps(route string, start time.Time) {
	m.qps.record(route, time.Now(), time.Since(start))
}

// applyRouteLatency sleeps for the configured response time of [route],
// if any override exists.
func (m *MockServer) applyRouteLatency(route string) {
	cfg := m.cfgSnapshot()
	if spec := cfg.latencyFor(route); spec != nil {
		time.Sleep(spec.sample())
	}
}

// ---------- lifecycle handlers ----------

func (m *MockServer) handleLifecycle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/__stats":
		m.handleStats(w, r)
	case path == "/__config":
		m.handleConfig(w, r)
	case path == "/__reset":
		m.handleReset(w, r)
	case r.Method == http.MethodPost && path == "/v1/sandboxes":
		m.handleCreate(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v1/sandboxes/"):
		m.handleDelete(w, r, strings.TrimPrefix(path, "/v1/sandboxes/"))
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/renew-expiration"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/sandboxes/"), "/renew-expiration")
		m.handleRenew(w, r, id)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/sandboxes/") && strings.Contains(path, "/endpoints/"):
		parts := strings.Split(strings.TrimPrefix(path, "/v1/sandboxes/"), "/endpoints/")
		m.handleEndpoint(w, r, parts[0])
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/v1/sandboxes/"):
		m.handleGet(w, r, strings.TrimPrefix(path, "/v1/sandboxes/"))
	default:
		writeError(w, http.StatusNotFound, "NOT_FOUND", "no such route: "+path)
	}
}

func (m *MockServer) handleCreate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer m.recordQps("lifecycle.create", start)
	_, _ = io.Copy(io.Discard, r.Body)

	cfg := m.cfgSnapshot()
	if cfg.CreateFailureRate > 0 && rand.Float64() < cfg.CreateFailureRate {
		m.stats.incCreateFailed()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "simulated provisioning failure")
		return
	}

	latency := cfg.CreateLatencyMs.sample()
	if override := cfg.latencyFor("lifecycle.create"); override != nil {
		latency = override.sample()
	}
	time.Sleep(latency)
	m.stats.recordCreateLatency(latency)

	now := time.Now().UTC()
	expiresAt := now.Add(cfg.DefaultTtl)
	id := m.newSandboxID()
	sandbox := &Sandbox{
		ID:        id,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		State:     "Pending",
	}
	m.mu.Lock()
	m.sandboxes[id] = sandbox
	m.mu.Unlock()

	go m.bootSandbox(id, cfg.BootDelayMs)

	m.stats.incCreated()
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"status":     sandboxStatus(sandbox, now),
		"createdAt":  now.Format(time.RFC3339),
		"expiresAt":  expiresAt.Format(time.RFC3339),
		"entrypoint": []string{"tail", "-f", "/dev/null"},
	})
}

func (m *MockServer) bootSandbox(id string, delayMs int64) {
	if delayMs <= 0 {
		delayMs = 1
	}
	time.Sleep(time.Duration(delayMs) * time.Millisecond)
	m.mu.Lock()
	if sb, ok := m.sandboxes[id]; ok && sb.State == "Pending" {
		sb.State = "Running"
	}
	m.mu.Unlock()
}

func (m *MockServer) handleGet(w http.ResponseWriter, r *http.Request, id string) {
	start := time.Now()
	defer m.recordQps("lifecycle.get", start)
	m.applyRouteLatency("lifecycle.get")
	_ = r.Body.Close()
	m.stats.incSandboxGets()
	m.mu.RLock()
	sb := m.sandboxes[id]
	m.mu.RUnlock()
	if sb == nil || !sb.alive(time.Now()) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "sandbox not found: "+id)
		return
	}
	writeJSON(w, http.StatusOK, m.sandboxInfo(sb))
}

func (m *MockServer) handleDelete(w http.ResponseWriter, r *http.Request, id string) {
	start := time.Now()
	defer m.recordQps("lifecycle.delete", start)
	m.applyRouteLatency("lifecycle.delete")
	_ = r.Body.Close()
	m.mu.Lock()
	sb := m.sandboxes[id]
	if sb != nil {
		sb.State = "Terminated"
	}
	m.mu.Unlock()
	m.stats.incKilled()
	// DELETE of an unknown sandbox still succeeds (best-effort semantics);
	// a killed sandbox's execd endpoint stops responding.
	w.WriteHeader(http.StatusNoContent)
}

func (m *MockServer) handleRenew(w http.ResponseWriter, r *http.Request, id string) {
	start := time.Now()
	defer m.recordQps("lifecycle.renew", start)
	m.applyRouteLatency("lifecycle.renew")
	defer r.Body.Close()
	m.stats.incRenews()
	m.mu.RLock()
	sb := m.sandboxes[id]
	m.mu.RUnlock()
	if sb == nil || !sb.alive(time.Now()) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "sandbox not found: "+id)
		return
	}
	var body struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ExpiresAt == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "expiresAt is required")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "expiresAt must be RFC3339: "+err.Error())
		return
	}
	m.mu.Lock()
	sb.ExpiresAt = expiresAt
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"expiresAt": expiresAt.Format(time.RFC3339)})
}

func (m *MockServer) handleEndpoint(w http.ResponseWriter, r *http.Request, id string) {
	start := time.Now()
	defer m.recordQps("lifecycle.endpoint", start)
	m.applyRouteLatency("lifecycle.endpoint")
	_ = r.Body.Close()
	m.stats.incEndpointGets()
	m.mu.RLock()
	sb := m.sandboxes[id]
	m.mu.RUnlock()
	if sb == nil || !sb.alive(time.Now()) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "sandbox not found: "+id)
		return
	}
	// The endpoint URL and token let the execd listener attribute requests
	// to this sandbox so boot state and poisoning can be enforced.
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": fmt.Sprintf("%s:%d", m.execdHost, m.execdPort),
		"headers":  map[string]string{"X-EXECD-ACCESS-TOKEN": execdToken(id)},
	})
}

func (m *MockServer) sandboxInfo(sb *Sandbox) map[string]any {
	return map[string]any{
		"id":         sb.ID,
		"status":     sandboxStatus(sb, time.Now()),
		"createdAt":  sb.CreatedAt.Format(time.RFC3339),
		"expiresAt":  sb.ExpiresAt.Format(time.RFC3339),
		"entrypoint": []string{"tail", "-f", "/dev/null"},
	}
}

// ---------- execd handlers ----------

func (m *MockServer) handleExecd(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	route := "execd.other"
	if r.URL.Path == "/ping" {
		route = "execd.ping"
	}
	defer m.recordQps(route, start)
	m.stats.incExecdRequests()
	token := r.Header.Get("X-EXECD-ACCESS-TOKEN")
	id := strings.TrimPrefix(token, "mock-token-")
	if token != "" && token == execdToken(id) {
		m.mu.RLock()
		sb := m.sandboxes[id]
		m.mu.RUnlock()
		if sb == nil || !sb.running(time.Now()) {
			// Not booted yet, expired, or killed. Fail fast and answer with
			// a non-retryable status (404): the SDK's retry interceptor
			// retries 5xx and transport errors with backoff, which would
			// pollute the readiness-poll timing this mock is meant to
			// measure. 404 makes the SDK poll at its configured interval
			// until ready. The readiness probe only starts paying the route
			// latency once the sandbox is actually up.
			writeError(w, http.StatusNotFound, "NOT_READY", "sandbox not ready: "+id)
			return
		}
		if sb.Poisoned {
			m.stats.incExecdPoisoned()
			writeError(w, http.StatusNotFound, "POISONED", "sandbox endpoint poisoned")
			return
		}
	}
	// A ready sandbox's requests pay the configured route latency.
	m.applyRouteLatency(route)
	cfg := m.cfgSnapshot()
	if cfg.ExecdFailureRate > 0 && rand.Float64() < cfg.ExecdFailureRate {
		m.stats.incExecdFailures()
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "simulated execd failure")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// ---------- control handlers ----------

func (m *MockServer) handleStats(w http.ResponseWriter, r *http.Request) {
	_ = r.Body.Close()
	stats := m.stats.snapshot()
	m.mu.RLock()
	alive := 0
	poisoned := 0
	now := time.Now()
	for _, sb := range m.sandboxes {
		if sb.alive(now) {
			alive++
		}
		if sb.Poisoned {
			poisoned++
		}
	}
	m.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":      stats,
		"alive":      alive,
		"aliveStats": m.alive.snapshot(time.Now()),
		"poisoned":   poisoned,
		"config":     m.cfgSnapshot(),
		"qps":        m.qps.snapshot(time.Now()),
		"serverTime": time.Now().UTC().Format(time.RFC3339),
	})
}

func (m *MockServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var f FaultConfig
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	m.cfgMu.Lock()
	m.cfg.applyFault(f)
	m.cfgMu.Unlock()
	if f.PoisonExisting {
		m.mu.Lock()
		for _, sb := range m.sandboxes {
			if sb.alive(time.Now()) {
				sb.Poisoned = true
			}
		}
		m.mu.Unlock()
	}
	if f.PoisonRate != nil {
		rate := *f.PoisonRate
		m.mu.Lock()
		for _, sb := range m.sandboxes {
			if sb.alive(time.Now()) && rand.Float64() < rate {
				sb.Poisoned = true
			}
		}
		m.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": m.cfgSnapshot()})
}

func (m *MockServer) handleReset(w http.ResponseWriter, r *http.Request) {
	_ = r.Body.Close()
	m.stats.reset()
	m.qps.reset(time.Now())
	m.alive.reset(time.Now())
	writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}

// ---------- helpers ----------

func (m *MockServer) newSandboxID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSeq++
	return fmt.Sprintf("sbx-mock-%d-%d", time.Now().UnixNano(), m.nextSeq)
}

func (m *MockServer) cfgSnapshot() Config {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return *m.cfg
}

func sandboxStatus(sb *Sandbox, now time.Time) map[string]any {
	return map[string]any{
		"state":            sb.State,
		"lastTransitionAt": sb.CreatedAt.Format(time.RFC3339),
	}
}

func execdToken(id string) string { return "mock-token-" + id }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"code": code, "message": message})
}

// Stats are the server-side counters exposed via /__stats. They let the
// benchmark driver validate pool behavior (no over-creation, stale cleanup,
// hit rate) and cross-check client-observed numbers.
type Stats struct {
	created          atomic.Int64
	createFailed     atomic.Int64
	killed           atomic.Int64
	renews           atomic.Int64
	sandboxGets      atomic.Int64
	endpointGets     atomic.Int64
	execdRequests    atomic.Int64
	execdFailures    atomic.Int64
	execdPoisoned    atomic.Int64
	latencyMu        sync.Mutex
	createLatencyMs  []int64
	maxCreateLatency atomic.Int64
}

type StatsSnapshot struct {
	Created            int64   `json:"created"`
	CreateFailed       int64   `json:"createFailed"`
	Killed             int64   `json:"killed"`
	Renews             int64   `json:"renews"`
	SandboxGets        int64   `json:"sandboxGets"`
	EndpointGets       int64   `json:"endpointGets"`
	ExecdRequests      int64   `json:"execdRequests"`
	ExecdFailures      int64   `json:"execdFailures"`
	ExecdPoisoned      int64   `json:"execdPoisoned"`
	CreateLatencyMsAvg float64 `json:"createLatencyMsAvg"`
	CreateLatencyMsP50 int64   `json:"createLatencyMsP50"`
	CreateLatencyMsP95 int64   `json:"createLatencyMsP95"`
	CreateLatencyMsP99 int64   `json:"createLatencyMsP99"`
	MaxCreateLatencyMs int64   `json:"maxCreateLatencyMs"`
}

func (s *Stats) incCreated()       { s.created.Add(1) }
func (s *Stats) incCreateFailed()  { s.createFailed.Add(1) }
func (s *Stats) incKilled()        { s.killed.Add(1) }
func (s *Stats) incRenews()        { s.renews.Add(1) }
func (s *Stats) incSandboxGets()   { s.sandboxGets.Add(1) }
func (s *Stats) incEndpointGets()  { s.endpointGets.Add(1) }
func (s *Stats) incExecdRequests() { s.execdRequests.Add(1) }
func (s *Stats) incExecdFailures() { s.execdFailures.Add(1) }
func (s *Stats) incExecdPoisoned() { s.execdPoisoned.Add(1) }

func (s *Stats) recordCreateLatency(d time.Duration) {
	ms := d.Milliseconds()
	s.latencyMu.Lock()
	s.createLatencyMs = append(s.createLatencyMs, ms)
	s.latencyMu.Unlock()
	if cur := s.maxCreateLatency.Load(); ms > cur {
		s.maxCreateLatency.CompareAndSwap(cur, ms)
	}
}

func (s *Stats) snapshot() StatsSnapshot {
	s.latencyMu.Lock()
	samples := append([]int64(nil), s.createLatencyMs...)
	s.latencyMu.Unlock()
	sorted := make([]int64, len(samples))
	copy(sorted, samples)
	// insertion sort: sample counts stay small for benchmark runs
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j] < sorted[j-1]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	percentile := func(p float64) int64 {
		if len(sorted) == 0 {
			return 0
		}
		idx := int(float64(len(sorted)-1) * p)
		return sorted[idx]
	}
	var sum int64
	for _, v := range sorted {
		sum += v
	}
	avg := 0.0
	if len(sorted) > 0 {
		avg = float64(sum) / float64(len(sorted))
	}
	return StatsSnapshot{
		Created:            s.created.Load(),
		CreateFailed:       s.createFailed.Load(),
		Killed:             s.killed.Load(),
		Renews:             s.renews.Load(),
		SandboxGets:        s.sandboxGets.Load(),
		EndpointGets:       s.endpointGets.Load(),
		ExecdRequests:      s.execdRequests.Load(),
		ExecdFailures:      s.execdFailures.Load(),
		ExecdPoisoned:      s.execdPoisoned.Load(),
		CreateLatencyMsAvg: avg,
		CreateLatencyMsP50: percentile(0.50),
		CreateLatencyMsP95: percentile(0.95),
		CreateLatencyMsP99: percentile(0.99),
		MaxCreateLatencyMs: s.maxCreateLatency.Load(),
	}
}

func (s *Stats) reset() {
	s.created.Store(0)
	s.createFailed.Store(0)
	s.killed.Store(0)
	s.renews.Store(0)
	s.sandboxGets.Store(0)
	s.endpointGets.Store(0)
	s.execdRequests.Store(0)
	s.execdFailures.Store(0)
	s.execdPoisoned.Store(0)
	s.maxCreateLatency.Store(0)
	s.latencyMu.Lock()
	s.createLatencyMs = nil
	s.latencyMu.Unlock()
}
