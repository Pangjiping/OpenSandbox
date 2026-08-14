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
	"sync"
	"time"
)

// DefaultStatsWindowSec is how many seconds of per-API request history the
// mock keeps for QPS analysis. 30 minutes covers a full default benchmark
// run; raise it with -stats-window-sec for longer soaks.
const DefaultStatsWindowSec = 1800

// qpsTracker records exact per-second request counts for one API route in a
// ring buffer. Snapshots expose totals, recent-window rates, and the full
// per-second series so the driver can plot pool load over time.
type qpsTracker struct {
	mu           sync.Mutex
	window       int64
	buckets      []int64 // ring of per-second counts
	secs         []int64 // wall-clock second each bucket covers
	startSec     int64   // first recorded second (0 until first request/reset)
	total        int64
	latencySumMs int64
	maxMs        int64
}

func newQpsTracker(windowSec int) *qpsTracker {
	return &qpsTracker{
		window:  int64(windowSec),
		buckets: make([]int64, windowSec),
		secs:    make([]int64, windowSec),
	}
}

func (t *qpsTracker) record(now time.Time, elapsed time.Duration) {
	sec := now.Unix()
	idx := sec % t.window
	t.mu.Lock()
	if t.secs[idx] != sec {
		// Lazy bucket reset: first request in this second.
		t.secs[idx] = sec
		t.buckets[idx] = 0
	}
	t.buckets[idx]++
	t.total++
	if t.startSec == 0 {
		t.startSec = sec
	}
	ms := elapsed.Milliseconds()
	t.latencySumMs += ms
	if ms > t.maxMs {
		t.maxMs = ms
	}
	t.mu.Unlock()
}

func (t *qpsTracker) reset(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i := range t.buckets {
		t.buckets[i] = 0
		t.secs[i] = 0
	}
	t.total = 0
	t.latencySumMs = 0
	t.maxMs = 0
	t.startSec = now.Unix()
}

type QpsSnapshot struct {
	Total       int64   `json:"total"`
	Qps1s       float64 `json:"qps1s"`
	Qps5s       float64 `json:"qps5s"`
	Qps60s      float64 `json:"qps60s"`
	SeriesStart int64   `json:"seriesStartUnixSec"`
	Series      []int64 `json:"series"`
	// AvgMs is the average handler latency for this route since the last reset.
	AvgMs float64 `json:"avgMs"`
	MaxMs int64   `json:"maxMs"`
}

// snapshot returns totals, rates over the trailing 1s/5s/60s windows (the
// current, possibly partial second counts toward qps1s), and the per-second
// series covering the retained window. Requests older than the ring are
// dropped, so for runs longer than the window the driver should poll /__stats
// and accumulate externally.
func (t *qpsTracker) snapshot(now time.Time) QpsSnapshot {
	sec := now.Unix()
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.startSec == 0 {
		t.startSec = sec
	}
	begin := t.startSec
	if sec-begin+1 > t.window {
		begin = sec - t.window + 1
	}

	avgLatency := 0.0
	if t.total > 0 {
		avgLatency = float64(t.latencySumMs) / float64(t.total)
	}

	series := make([]int64, 0, sec-begin+1)
	for s := begin; s <= sec; s++ {
		idx := s % t.window
		count := t.buckets[idx]
		if t.secs[idx] != s {
			count = 0
		}
		series = append(series, count)
	}

	rate := func(windowSec int64) float64 {
		if windowSec <= 0 {
			return 0
		}
		start := sec - windowSec + 1
		if start < begin {
			start = begin
		}
		if sec < start {
			return 0
		}
		var sum int64
		for s := start; s <= sec; s++ {
			idx := s % t.window
			if t.secs[idx] == s {
				sum += t.buckets[idx]
			}
		}
		return float64(sum) / float64(sec-start+1)
	}

	return QpsSnapshot{
		Total:       t.total,
		Qps1s:       rate(1),
		Qps5s:       rate(5),
		Qps60s:      rate(60),
		SeriesStart: begin,
		Series:      series,
		AvgMs:       avgLatency,
		MaxMs:       t.maxMs,
	}
}

// QpsRegistry tracks one tracker per API route.
type QpsRegistry struct {
	windowSec int
	mu        sync.RWMutex
	trackers  map[string]*qpsTracker
}

func newQpsRegistry(windowSec int) *QpsRegistry {
	return &QpsRegistry{
		windowSec: windowSec,
		trackers:  make(map[string]*qpsTracker),
	}
}

func (r *QpsRegistry) record(route string, now time.Time, elapsed time.Duration) {
	r.mu.RLock()
	t := r.trackers[route]
	r.mu.RUnlock()
	if t == nil {
		r.mu.Lock()
		t = r.trackers[route]
		if t == nil {
			t = newQpsTracker(r.windowSec)
			r.trackers[route] = t
		}
		r.mu.Unlock()
	}
	t.record(now, elapsed)
}

func (r *QpsRegistry) reset(now time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.trackers {
		t.reset(now)
	}
}

func (r *QpsRegistry) snapshot(now time.Time) map[string]QpsSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]QpsSnapshot, len(r.trackers))
	for route, t := range r.trackers {
		out[route] = t.snapshot(now)
	}
	return out
}

// GaugeSnapshot is the per-second view of a gauge (e.g. alive sandboxes).
type GaugeSnapshot struct {
	Max         int64   `json:"max"`
	SeriesStart int64   `json:"seriesStartUnixSec"`
	Series      []int64 `json:"series"`
}

// gaugeTracker keeps the per-second peak of a gauge (ring buffer) plus the
// all-time max since the last reset.
type gaugeTracker struct {
	mu       sync.Mutex
	window   int64
	buckets  []int64
	secs     []int64
	startSec int64
	maxAll   int64
}

func newGaugeTracker(windowSec int) *gaugeTracker {
	return &gaugeTracker{
		window:  int64(windowSec),
		buckets: make([]int64, windowSec),
		secs:    make([]int64, windowSec),
	}
}

func (g *gaugeTracker) record(now time.Time, value int64) {
	sec := now.Unix()
	idx := sec % g.window
	g.mu.Lock()
	if g.secs[idx] != sec {
		g.secs[idx] = sec
		g.buckets[idx] = value
	} else if value > g.buckets[idx] {
		g.buckets[idx] = value
	}
	if value > g.maxAll {
		g.maxAll = value
	}
	if g.startSec == 0 {
		g.startSec = sec
	}
	g.mu.Unlock()
}

func (g *gaugeTracker) reset(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := range g.buckets {
		g.buckets[i] = 0
		g.secs[i] = 0
	}
	g.maxAll = 0
	g.startSec = now.Unix()
}

func (g *gaugeTracker) snapshot(now time.Time) GaugeSnapshot {
	sec := now.Unix()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.startSec == 0 {
		g.startSec = sec
	}
	begin := g.startSec
	if sec-begin+1 > g.window {
		begin = sec - g.window + 1
	}
	series := make([]int64, 0, sec-begin+1)
	for s := begin; s <= sec; s++ {
		idx := s % g.window
		value := g.buckets[idx]
		if g.secs[idx] != s {
			value = 0
		}
		series = append(series, value)
	}
	return GaugeSnapshot{Max: g.maxAll, SeriesStart: begin, Series: series}
}
