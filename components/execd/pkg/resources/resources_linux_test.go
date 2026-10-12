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
	"os"
	"path/filepath"
	"testing"
	"time"
)

// overridePaths points the discovery inputs at a fake cgroup tree and
// restores the originals after the test.
func overridePaths(t *testing.T, selfCgroup string, v2Dir, v1MemoryDir string, v1CPUDirs []string) {
	t.Helper()
	origCgroup, origMounts := procSelfCgroupFile, procMountsFile
	origV2, origV1Mem, origV1CPU := cgroupV2Dir, cgroupV1MemoryDir, cgroupV1CPUDirs
	cgroupFile := filepath.Join(t.TempDir(), "self-cgroup")
	if err := os.WriteFile(cgroupFile, []byte(selfCgroup), 0o644); err != nil {
		t.Fatal(err)
	}
	procSelfCgroupFile = cgroupFile
	procMountsFile = filepath.Join(t.TempDir(), "mounts") // missing: default dirs must resolve
	cgroupV2Dir, cgroupV1MemoryDir, cgroupV1CPUDirs = v2Dir, v1MemoryDir, v1CPUDirs
	t.Cleanup(func() {
		procSelfCgroupFile, procMountsFile = origCgroup, origMounts
		cgroupV2Dir, cgroupV1MemoryDir, cgroupV1CPUDirs = origV2, origV1Mem, origV1CPU
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNewCgroupBackendV2(t *testing.T) {
	root := t.TempDir()
	sandbox := filepath.Join(root, "sandbox")
	writeFile(t, filepath.Join(root, "cgroup.controllers"), "")
	writeFile(t, filepath.Join(sandbox, "cpu.stat"), "usage_usec 1000000\nuser_usec 10\nsystem_usec 10\n")
	writeFile(t, filepath.Join(sandbox, "cpu.max"), "100000 100000\n")
	writeFile(t, filepath.Join(sandbox, "memory.current"), "52428800\n")
	writeFile(t, filepath.Join(sandbox, "memory.max"), "209715200\n")
	overridePaths(t, "0::/sandbox\n", root, "", nil)

	backend, err := newCgroupBackend()
	if err != nil {
		t.Fatalf("newCgroupBackend: %v", err)
	}
	cg, ok := backend.(*cgroupBackend)
	if !ok {
		t.Fatalf("backend = %T, want *cgroupBackend", backend)
	}
	if got := cg.cpuCount(); got != 1 {
		t.Fatalf("cpuCount = %v, want 1 (quota 100000/100000)", got)
	}
	stats, err := backend.memoryStats()
	if err != nil {
		t.Fatalf("memoryStats: %v", err)
	}
	if stats.UsedBytes != 52428800 || stats.TotalBytes != 209715200 {
		t.Fatalf("memoryStats = %+v, want used=52428800 total=209715200", stats)
	}

	// Advance the cumulative CPU time by 0.05 core-seconds in the middle of
	// the 100ms sampling window: half a core on a 1-core quota = ~50%.
	statPath := filepath.Join(sandbox, "cpu.stat")
	bumped := make(chan struct{})
	go func() {
		defer close(bumped)
		time.Sleep(25 * time.Millisecond)
		_ = os.WriteFile(statPath, []byte("usage_usec 1050000\nuser_usec 10\nsystem_usec 10\n"), 0o644)
	}()
	percent, err := backend.cpuPercent(100 * time.Millisecond)
	<-bumped
	if err != nil {
		t.Fatalf("cpuPercent: %v", err)
	}
	if percent < 25 || percent > 150 {
		t.Fatalf("cpuPercent = %v, want ~50 (tolerance for scheduling jitter)", percent)
	}
}

func TestNewCgroupBackendV2UnlimitedFallsBackToHost(t *testing.T) {
	root := t.TempDir()
	sandbox := filepath.Join(root, "sandbox")
	writeFile(t, filepath.Join(root, "cgroup.controllers"), "")
	writeFile(t, filepath.Join(sandbox, "cpu.stat"), "usage_usec 1000000\n")
	writeFile(t, filepath.Join(sandbox, "cpu.max"), "max 100000\n")
	writeFile(t, filepath.Join(sandbox, "memory.current"), "52428800\n")
	writeFile(t, filepath.Join(sandbox, "memory.max"), "max\n")
	overridePaths(t, "0::/sandbox\n", root, "", nil)

	if _, err := newCgroupBackend(); err != errNoLimitedCgroup {
		t.Fatalf("newCgroupBackend err = %v, want %v", err, errNoLimitedCgroup)
	}
	host := newBackend()
	if _, ok := host.(hostBackend); !ok {
		t.Fatalf("newBackend = %T, want hostBackend", host)
	}
}

func TestNewCgroupBackendV1(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "memory", "sandbox", "memory.usage_in_bytes"), "104857600\n")
	writeFile(t, filepath.Join(root, "memory", "sandbox", "memory.limit_in_bytes"), "2147483648\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpuacct.usage"), "50000000\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpu.cfs_quota_us"), "200000\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpu.cfs_period_us"), "100000\n")
	overridePaths(t, "12:memory:/sandbox\n3:cpu,cpuacct:/sandbox\n",
		"", filepath.Join(root, "memory"), []string{filepath.Join(root, "cpu,cpuacct")})

	backend, err := newCgroupBackend()
	if err != nil {
		t.Fatalf("newCgroupBackend: %v", err)
	}
	if got := backend.cpuCount(); got != 2 {
		t.Fatalf("cpuCount = %v, want 2 (quota 200000/100000)", got)
	}
	stats, err := backend.memoryStats()
	if err != nil {
		t.Fatalf("memoryStats: %v", err)
	}
	if stats.UsedBytes != 104857600 || stats.TotalBytes != 2147483648 {
		t.Fatalf("memoryStats = %+v, want used=104857600 total=2147483648", stats)
	}
	cg, ok := backend.(*cgroupBackend)
	if !ok {
		t.Fatalf("backend = %T, want *cgroupBackend", backend)
	}
	uSec, err := cg.cpuUSec()
	if err != nil {
		t.Fatalf("cpuUSec: %v", err)
	}
	if uSec != 50000 { // 50000000 ns -> 50000 µs
		t.Fatalf("cpuUSec = %d, want 50000", uSec)
	}
}

func TestNewCgroupBackendV1UnlimitedFallsBackToHost(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "memory", "sandbox", "memory.usage_in_bytes"), "104857600\n")
	writeFile(t, filepath.Join(root, "memory", "sandbox", "memory.limit_in_bytes"), "9223372036854771712\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpuacct.usage"), "50000000\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpu.cfs_quota_us"), "-1\n")
	writeFile(t, filepath.Join(root, "cpu,cpuacct", "sandbox", "cpu.cfs_period_us"), "100000\n")
	overridePaths(t, "12:memory:/sandbox\n3:cpu,cpuacct:/sandbox\n",
		"", filepath.Join(root, "memory"), []string{filepath.Join(root, "cpu,cpuacct")})

	if _, err := newCgroupBackend(); err != errNoLimitedCgroup {
		t.Fatalf("newCgroupBackend err = %v, want %v", err, errNoLimitedCgroup)
	}
	if _, ok := newBackend().(hostBackend); !ok {
		t.Fatal("newBackend = cgroup backend, want hostBackend")
	}
}

func TestCPUUSecSinceLastInterval(t *testing.T) {
	root := t.TempDir()
	sandbox := filepath.Join(root, "sandbox")
	writeFile(t, filepath.Join(root, "cgroup.controllers"), "")
	writeFile(t, filepath.Join(sandbox, "cpu.stat"), "usage_usec 1000000\n")
	writeFile(t, filepath.Join(sandbox, "cpu.max"), "100000 100000\n")
	writeFile(t, filepath.Join(sandbox, "memory.current"), "1\n")
	writeFile(t, filepath.Join(sandbox, "memory.max"), "4096\n")
	overridePaths(t, "0::/sandbox\n", root, "", nil)

	backend, err := newCgroupBackend()
	if err != nil {
		t.Fatalf("newCgroupBackend: %v", err)
	}
	// First since-last-call reports 0, then the delta against the previous
	// call: 0.1 core-seconds in a 100ms window = 1 saturated core on a
	// 1-core quota.
	first, err := backend.cpuPercent(0)
	if err != nil {
		t.Fatalf("cpuPercent(0): %v", err)
	}
	if first != 0 {
		t.Fatalf("first cpuPercent(0) = %v, want 0", first)
	}
	writeFile(t, filepath.Join(sandbox, "cpu.stat"), "usage_usec 1100000\n")
	time.Sleep(100 * time.Millisecond)
	second, err := backend.cpuPercent(0)
	if err != nil {
		t.Fatalf("cpuPercent(0): %v", err)
	}
	if second < 50 || second > 200 {
		t.Fatalf("cpuPercent(0) = %v, want ~100 (tolerance for scheduling jitter)", second)
	}
}
