//go:build linux

// Copyright 2026 The OpenSandbox Authors
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

package resources

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Test-overridable input paths.
var (
	procSelfCgroupFile = "/proc/self/cgroup"
	procMountsFile     = "/proc/self/mounts"
	cgroupV2Dir        = "/sys/fs/cgroup"
	cgroupV1MemoryDir  = "/sys/fs/cgroup/memory"
	cgroupV1CPUDirs    = []string{"/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpuacct"}
)

// errNoLimitedCgroup: no visible cgroup carries a configured resource limit,
// so the cgroup cannot describe a sandbox resource boundary.
var errNoLimitedCgroup = errors.New("no sandbox cgroup with configured resource limits")

// newBackend prefers the sandbox cgroup and falls back to the host view:
// without a configured limit the cgroup does not represent the sandbox
// boundary, and in a microVM guest the host view is the sandbox.
func newBackend() backend {
	if b, err := newCgroupBackend(); err == nil {
		return b
	}
	return hostBackend{}
}

func newCgroupBackend() (backend, error) {
	data, err := os.ReadFile(procSelfCgroupFile)
	if err != nil {
		return nil, err
	}
	entries := parseCgroupEntries(data)
	if rel := cgroupV2RelPath(entries); rel != "" {
		if b, err := newCgroupV2Backend(rel); err == nil {
			return b, nil
		}
	}
	if b, err := newCgroupV1Backend(
		cgroupV1RelPath(entries, "memory"),
		cgroupV1RelPath(entries, "cpu", "cpuacct"),
	); err == nil {
		return b, nil
	}
	return nil, errNoLimitedCgroup
}

// cgroupBackend reads the sandbox's own cgroup interface files: the sandbox
// subtree's real CPU time, CPU quota, and memory usage/limit.
type cgroupBackend struct {
	usagePath    string  // cumulative CPU time file; empty when unavailable
	usageNS      bool    // usagePath counts nanoseconds (cgroup v1)
	quotaCores   float64 // >0 when a CPU quota is configured
	memUsedPath  string  // empty when unavailable
	memLimitPath string  // empty when no limit file is available
	memV1        bool    // memLimitPath uses the v1 huge-value encoding

	lastMu   sync.Mutex
	lastUSec uint64
	lastWall time.Time
	haveLast bool
}

func newCgroupV2Backend(relPath string) (backend, error) {
	mount, err := cgroupV2Mount()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(mount, filepath.FromSlash(relPath))
	usagePath := filepath.Join(dir, "cpu.stat")
	memUsedPath := filepath.Join(dir, "memory.current")
	memLimitPath := filepath.Join(dir, "memory.max")
	for _, path := range []string{usagePath, memUsedPath, memLimitPath} {
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
	}
	quotaData, err := os.ReadFile(filepath.Join(dir, "cpu.max"))
	if err != nil {
		return nil, err
	}
	quota, period, cpuLimited, ok := parseCPUMax(quotaData)
	if !ok {
		return nil, fmt.Errorf("unparseable cpu.max under %s", dir)
	}
	memLimitData, err := os.ReadFile(memLimitPath)
	if err != nil {
		return nil, err
	}
	_, memLimited, ok := parseMemoryMax(memLimitData)
	if !ok {
		return nil, fmt.Errorf("unparseable memory.max under %s", dir)
	}
	if !cpuLimited && !memLimited {
		return nil, errNoLimitedCgroup
	}
	b := &cgroupBackend{
		usagePath:    usagePath,
		memUsedPath:  memUsedPath,
		memLimitPath: memLimitPath,
	}
	if cpuLimited {
		b.quotaCores = quotaCores(quota, period)
	}
	return b, nil
}

func newCgroupV1Backend(memRel, cpuRel string) (backend, error) {
	b := &cgroupBackend{}

	if memRel != "" {
		if dir, err := cgroupV1MountDir([]string{cgroupV1MemoryDir}, "memory"); err == nil {
			memDir := filepath.Join(dir, filepath.FromSlash(memRel))
			usedPath := filepath.Join(memDir, "memory.usage_in_bytes")
			limitPath := filepath.Join(memDir, "memory.limit_in_bytes")
			if fileExists(usedPath) && fileExists(limitPath) {
				b.memUsedPath, b.memLimitPath, b.memV1 = usedPath, limitPath, true
			}
		}
	}

	if cpuRel != "" {
		if dir, err := cgroupV1MountDir(cgroupV1CPUDirs, "cpu", "cpuacct"); err == nil {
			cpuDir := filepath.Join(dir, filepath.FromSlash(cpuRel))
			usagePath := filepath.Join(cpuDir, "cpuacct.usage")
			if fileExists(usagePath) {
				b.usagePath, b.usageNS = usagePath, true
				b.quotaCores = v1QuotaCores(cpuDir)
			}
		}
	}

	if b.usagePath == "" && b.memUsedPath == "" {
		return nil, errNoLimitedCgroup
	}
	if !b.hasAnyLimit() {
		return nil, errNoLimitedCgroup
	}
	return b, nil
}

// hasAnyLimit reports whether a real CPU quota or memory limit is
// configured. Without any limit the cgroup does not bound the sandbox: it
// cannot distinguish a constrained container from an unconstrained VM guest.
func (b *cgroupBackend) hasAnyLimit() bool {
	if b.quotaCores > 0 {
		return true
	}
	if b.memLimitPath == "" {
		return false
	}
	data, err := os.ReadFile(b.memLimitPath)
	if err != nil {
		return false
	}
	if b.memV1 {
		_, limited, _ := parseV1MemoryLimit(data)
		return limited
	}
	_, limited, _ := parseMemoryMax(data)
	return limited
}

func (b *cgroupBackend) cpuPercent(interval time.Duration) (float64, error) {
	if b.usagePath == "" {
		return 0, errors.New("no cgroup CPU usage file available")
	}
	capacity := b.cpuCount()
	if interval > 0 {
		prev, err := b.cpuUSec()
		if err != nil {
			return 0, err
		}
		time.Sleep(interval)
		cur, err := b.cpuUSec()
		if err != nil {
			return 0, err
		}
		return cpuDeltaPercent(prev, cur, interval, capacity), nil
	}
	b.lastMu.Lock()
	defer b.lastMu.Unlock()
	cur, err := b.cpuUSec()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	if !b.haveLast {
		b.lastUSec, b.lastWall, b.haveLast = cur, now, true
		return 0, nil
	}
	percent := cpuDeltaPercent(b.lastUSec, cur, now.Sub(b.lastWall), capacity)
	b.lastUSec, b.lastWall = cur, now
	return percent, nil
}

func (b *cgroupBackend) cpuCount() float64 {
	if b.quotaCores > 0 {
		return b.quotaCores
	}
	return float64(runtime.GOMAXPROCS(-1))
}

func (b *cgroupBackend) memoryStats() (MemoryUsage, error) {
	if b.memUsedPath == "" {
		return hostBackend{}.memoryStats()
	}
	data, err := os.ReadFile(b.memUsedPath)
	if err != nil {
		return MemoryUsage{}, err
	}
	used, ok := parseSingleInt(data)
	if !ok {
		return MemoryUsage{}, fmt.Errorf("unparseable memory usage file %s", b.memUsedPath)
	}
	if used < 0 {
		used = 0
	}
	if b.memLimitPath != "" {
		if limitData, err := os.ReadFile(b.memLimitPath); err == nil {
			var limit int64
			var limited bool
			if b.memV1 {
				limit, limited, _ = parseV1MemoryLimit(limitData)
			} else {
				limit, limited, _ = parseMemoryMax(limitData)
			}
			if limited {
				return MemoryUsage{UsedBytes: used, TotalBytes: max(limit, 0)}, nil
			}
		}
	}
	// No configured limit: capacity is the host (or VM) total.
	host, err := hostBackend{}.memoryStats()
	if err != nil {
		return MemoryUsage{}, err
	}
	return MemoryUsage{UsedBytes: used, TotalBytes: host.TotalBytes}, nil
}

// cpuUSec reads the cumulative sandbox CPU time in microseconds.
func (b *cgroupBackend) cpuUSec() (uint64, error) {
	data, err := os.ReadFile(b.usagePath)
	if err != nil {
		return 0, err
	}
	var raw uint64
	var ok bool
	if b.usageNS {
		if raw, ok = parseSingleUint(data); !ok {
			return 0, fmt.Errorf("unparseable CPU usage file %s", b.usagePath)
		}
		raw /= 1000 // ns -> µs
		return raw, nil
	}
	if raw, ok = parseCPUStatUsageUSec(data); !ok {
		return 0, fmt.Errorf("unparseable CPU usage file %s", b.usagePath)
	}
	return raw, nil
}

// v1QuotaCores reads the v1 CFS quota files of a cpu controller directory
// and returns the configured core count (0 when unlimited or unreadable).
func v1QuotaCores(cpuDir string) float64 {
	quotaData, err := os.ReadFile(filepath.Join(cpuDir, "cpu.cfs_quota_us"))
	if err != nil {
		return 0
	}
	periodData, err := os.ReadFile(filepath.Join(cpuDir, "cpu.cfs_period_us"))
	if err != nil {
		return 0
	}
	quota, limited, ok := parseV1QuotaUS(quotaData)
	if !ok || !limited {
		return 0
	}
	period, ok := parseSingleInt(periodData)
	if !ok || period <= 0 {
		return 0
	}
	return quotaCores(quota, period)
}

// cgroupV2Mount locates the cgroup v2 filesystem mount.
func cgroupV2Mount() (string, error) {
	if fileExists(filepath.Join(cgroupV2Dir, "cgroup.controllers")) {
		return cgroupV2Dir, nil
	}
	return scanMounts(func(_ string, fstype string, _ []string) bool {
		return fstype == "cgroup2"
	})
}

// cgroupV1MountDir locates a v1 controller hierarchy mount: the default
// directories first, then /proc/self/mounts by controller name.
func cgroupV1MountDir(defaultDirs []string, controllers ...string) (string, error) {
	for _, dir := range defaultDirs {
		if _, err := os.Stat(dir); err == nil {
			return dir, nil
		}
	}
	return scanMounts(func(_ string, fstype string, options []string) bool {
		if fstype != "cgroup" {
			return false
		}
		for _, controller := range controllers {
			// /proc/self/mounts packs options into one comma-separated
			// field, e.g. "rw,nosuid,nodev,cpu,cpuacct".
			for _, field := range options {
				for _, opt := range strings.Split(field, ",") {
					if opt == controller {
						return true
					}
				}
			}
		}
		return false
	})
}

func scanMounts(match func(mountPoint, fstype string, options []string) bool) (string, error) {
	data, err := os.ReadFile(procMountsFile)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if match(fields[1], fields[2], fields[3:]) {
			return fields[1], nil
		}
	}
	return "", errors.New("no matching cgroup mount in " + procMountsFile)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
