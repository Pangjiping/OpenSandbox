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
	"math"
	"math/rand"
	"os"
	"time"
)

// Config models one mock-server run. It is loaded from a JSON file at startup
// and can be mutated at runtime through POST /__config (see FaultConfig).
type Config struct {
	// CreateLatencyMs controls how long POST /v1/sandboxes takes before
	// returning, mimicking real sandbox provisioning time.
	CreateLatencyMs LatencySpec `json:"createLatencyMs"`
	// CreateFailureRate is the probability [0,1] that POST /v1/sandboxes
	// returns HTTP 500 instead of creating a sandbox.
	CreateFailureRate float64 `json:"createFailureRate"`
	// BootDelayMs is how long a freshly created sandbox stays in Pending
	// state. Its execd endpoint (and therefore the SDK readiness probe)
	// only succeeds after the boot delay elapses.
	BootDelayMs int64 `json:"bootDelayMs"`
	// ExecdFailureRate is the probability [0,1] that any execd request
	// returns HTTP 500.
	ExecdFailureRate float64 `json:"execdFailureRate"`
	// DefaultTtl is the server-side lifetime assigned to created sandboxes
	// when the request does not carry a timeout. Sandboxes are reaped at
	// expiry: lifecycle lookups and execd pings start failing.
	DefaultTtl        time.Duration `json:"-"`
	DefaultTtlSeconds int64         `json:"defaultTtlSeconds"`
	// LatencyOverrides controls the response time of every other API route
	// (lifecycle.get, lifecycle.delete, lifecycle.renew, lifecycle.endpoint,
	// execd.ping, execd.other). Routes without an override respond
	// immediately. An entry for lifecycle.create overrides CreateLatencyMs.
	LatencyOverrides map[string]LatencySpec `json:"latencyOverrides"`
}

type LatencySpec struct {
	// Distribution: "lognormal" (default), "uniform", or "fixed".
	Distribution string  `json:"distribution"`
	MeanMs       float64 `json:"meanMs"`
	StddevMs     float64 `json:"stddevMs"`
	MinMs        float64 `json:"minMs"`
	// MaxMs is the upper bound for "uniform" sampling.
	MaxMs float64 `json:"maxMs"`
}

// FaultConfig is the mutable runtime subset of Config, updated via
// POST /__config. Fields are optional; absent fields keep current values.
type FaultConfig struct {
	CreateFailureRate *float64     `json:"createFailureRate"`
	ExecdFailureRate  *float64     `json:"execdFailureRate"`
	BootDelayMs       *int64       `json:"bootDelayMs"`
	CreateLatencyMs   *LatencySpec `json:"createLatencyMs"`
	// LatencyOverrides replaces the whole per-route response-time map when
	// present (even when empty).
	LatencyOverrides *map[string]LatencySpec `json:"latencyOverrides"`
	// PoisonExisting flips every currently-alive sandbox into a poisoned
	// state: its execd endpoint starts failing so SDK connects to it break.
	// Newly created sandboxes are unaffected. Used to simulate stale idle
	// sandboxes (e.g. sandboxes that died server-side).
	PoisonExisting bool `json:"poisonExisting"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{
		// Default response-time profile: create and delete take a uniform
		// 300-800ms, execd ping a uniform 1-5s (readiness probes are slow),
		// every other API a uniform 50-100ms.
		CreateLatencyMs: LatencySpec{
			Distribution: "uniform",
			MinMs:        300,
			MaxMs:        800,
		},
		LatencyOverrides: map[string]LatencySpec{
			"lifecycle.delete":   {Distribution: "uniform", MinMs: 300, MaxMs: 800},
			"lifecycle.get":      {Distribution: "uniform", MinMs: 50, MaxMs: 100},
			"lifecycle.renew":    {Distribution: "uniform", MinMs: 50, MaxMs: 100},
			"lifecycle.endpoint": {Distribution: "uniform", MinMs: 50, MaxMs: 100},
			"execd.ping":         {Distribution: "uniform", MinMs: 1000, MaxMs: 5000},
			"execd.other":        {Distribution: "uniform", MinMs: 50, MaxMs: 100},
		},
		DefaultTtlSeconds: 3600,
	}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		// The default latencyOverrides map is pre-seeded, and encoding/json
		// merges into existing maps instead of replacing them. Detect whether
		// the file mentions the key and drop the defaults first so an empty
		// map in the file means "no route latency" rather than "keep defaults".
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(raw, &keys); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		if _, ok := keys["latencyOverrides"]; ok {
			cfg.LatencyOverrides = nil
		}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if cfg.CreateLatencyMs.Distribution == "" {
		cfg.CreateLatencyMs.Distribution = "lognormal"
	}
	cfg.DefaultTtl = time.Duration(cfg.DefaultTtlSeconds) * time.Second
	return cfg, nil
}

func (cfg *Config) applyFault(f FaultConfig) {
	if f.CreateFailureRate != nil {
		cfg.CreateFailureRate = *f.CreateFailureRate
	}
	if f.ExecdFailureRate != nil {
		cfg.ExecdFailureRate = *f.ExecdFailureRate
	}
	if f.BootDelayMs != nil {
		cfg.BootDelayMs = *f.BootDelayMs
	}
	if f.CreateLatencyMs != nil {
		cfg.CreateLatencyMs = *f.CreateLatencyMs
	}
	if f.LatencyOverrides != nil {
		cfg.LatencyOverrides = *f.LatencyOverrides
	}
}

// latencyFor returns the latency spec for one API route, or nil when the
// route should respond immediately.
func (cfg *Config) latencyFor(route string) *LatencySpec {
	if cfg.LatencyOverrides != nil {
		if spec, ok := cfg.LatencyOverrides[route]; ok {
			return &spec
		}
	}
	return nil
}

// sample returns a latency duration drawn from the configured distribution.
// Uses math/rand's global functions, which are goroutine-safe.
func (s *LatencySpec) sample() time.Duration {
	switch s.Distribution {
	case "fixed":
		return time.Duration(s.MeanMs) * time.Millisecond
	case "uniform":
		lo := s.MinMs
		hi := s.MaxMs
		if hi <= lo {
			hi = s.MeanMs
		}
		if hi < lo {
			hi, lo = lo, hi
		}
		ms := lo + rand.Float64()*(hi-lo)
		return time.Duration(ms) * time.Millisecond
	default: // lognormal
		mean := math.Max(s.MeanMs, 0.001)
		stddev := math.Max(s.StddevMs, 0.001)
		mu := math.Log(mean * mean / math.Sqrt(mean*mean+stddev*stddev))
		sigma := math.Sqrt(math.Log(1 + stddev*stddev/(mean*mean)))
		v := mu + sigma*rand.NormFloat64()
		ms := math.Exp(v)
		if ms < s.MinMs {
			ms = s.MinMs
		}
		return time.Duration(ms) * time.Millisecond
	}
}
