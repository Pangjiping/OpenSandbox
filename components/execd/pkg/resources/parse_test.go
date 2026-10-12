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
	"testing"
	"time"
)

func TestParseCgroupEntries(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantV2      string
		wantV1CPU   string
		wantV1Mem   string
		noV2Because bool
	}{
		{
			name:   "pure cgroup v2",
			data:   "0::/system.slice/docker/abc\n",
			wantV2: "/system.slice/docker/abc",
		},
		{
			name:      "pure cgroup v1",
			data:      "10:cpuset:/\n12:memory:/sandbox\n3:cpu,cpuacct:/sandbox\n",
			wantV1CPU: "/sandbox",
			wantV1Mem: "/sandbox",
		},
		{
			name:        "hybrid host refuses v2",
			data:        "10:cpuset:/a\n0::/\n12:memory:/x\n",
			wantV1Mem:   "/x",
			noV2Because: true,
		},
		{
			name: "empty",
			data: "",
		},
		{
			name:   "malformed lines skipped",
			data:   "garbage\n0::\n0::/ok\n",
			wantV2: "/ok",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := parseCgroupEntries([]byte(tt.data))
			if got := cgroupV2RelPath(entries); tt.noV2Because {
				if got != "" {
					t.Fatalf("cgroupV2RelPath = %q, want empty", got)
				}
			} else if got != tt.wantV2 {
				t.Fatalf("cgroupV2RelPath = %q, want %q", got, tt.wantV2)
			}
			if got := cgroupV1RelPath(entries, "cpu", "cpuacct"); got != tt.wantV1CPU {
				t.Fatalf("cgroupV1RelPath(cpu) = %q, want %q", got, tt.wantV1CPU)
			}
			if got := cgroupV1RelPath(entries, "memory"); got != tt.wantV1Mem {
				t.Fatalf("cgroupV1RelPath(memory) = %q, want %q", got, tt.wantV1Mem)
			}
		})
	}
}

func TestParseCPUStatUsageUSec(t *testing.T) {
	data := []byte("usage_usec 123456\nuser_usec 1000\nsystem_usec 2000\nnr_periods 0\n")
	if got, ok := parseCPUStatUsageUSec(data); !ok || got != 123456 {
		t.Fatalf("parseCPUStatUsageUSec = (%d, %v), want (123456, true)", got, ok)
	}
	for _, data := range []string{"", "user_usec 1\n", "usage_usec abc\n", "usage_usec\n"} {
		if _, ok := parseCPUStatUsageUSec([]byte(data)); ok {
			t.Fatalf("parseCPUStatUsageUSec(%q) should fail", data)
		}
	}
}

func TestParseSingleUint(t *testing.T) {
	if got, ok := parseSingleUint([]byte("  50000000\n")); !ok || got != 50000000 {
		t.Fatalf("parseSingleUint = (%d, %v), want (50000000, true)", got, ok)
	}
	if _, ok := parseSingleUint([]byte("-1")); ok {
		t.Fatal("parseSingleUint(-1) should fail")
	}
}

func TestParseCPUMax(t *testing.T) {
	quota, period, limited, ok := parseCPUMax([]byte("100000 100000\n"))
	if !ok || !limited || quota != 100000 || period != 100000 {
		t.Fatalf("parseCPUMax = (%d, %d, %v, %v), want limited 1-core quota", quota, period, limited, ok)
	}
	if _, period, limited, ok = parseCPUMax([]byte("max 100000\n")); !ok || limited || period != 100000 {
		t.Fatalf("parseCPUMax(max) = limited=%v ok=%v, want unlimited ok", limited, ok)
	}
	for _, data := range []string{"", "100000\n", "max\n", "abc 100000\n", "100000 abc\n", "100000 0\n", "-5 100000\n"} {
		if _, _, _, ok := parseCPUMax([]byte(data)); ok {
			t.Fatalf("parseCPUMax(%q) should fail", data)
		}
	}
}

func TestQuotaCores(t *testing.T) {
	tests := []struct {
		quota, period int64
		want          float64
	}{
		{100000, 100000, 1},
		{200000, 100000, 2},
		{150000, 100000, 2}, // rounds up to whole cores
		{50000, 100000, 1},
		{0, 100000, 0},
		{100000, 0, 0},
		{-1, 100000, 0},
	}
	for _, tt := range tests {
		if got := quotaCores(tt.quota, tt.period); got != tt.want {
			t.Fatalf("quotaCores(%d, %d) = %v, want %v", tt.quota, tt.period, got, tt.want)
		}
	}
}

func TestParseMemoryMax(t *testing.T) {
	if limit, limited, ok := parseMemoryMax([]byte("209715200\n")); !ok || !limited || limit != 209715200 {
		t.Fatalf("parseMemoryMax = (%d, %v, %v), want (209715200, true, true)", limit, limited, ok)
	}
	if _, limited, ok := parseMemoryMax([]byte("max\n")); !ok || limited {
		t.Fatalf("parseMemoryMax(max) = limited=%v ok=%v, want unlimited ok", limited, ok)
	}
	if _, _, ok := parseMemoryMax([]byte("abc\n")); ok {
		t.Fatal("parseMemoryMax(abc) should fail")
	}
}

func TestParseV1MemoryLimit(t *testing.T) {
	limit, limited, ok := parseV1MemoryLimit([]byte("2147483648\n"))
	if !ok || !limited || limit != 2147483648 {
		t.Fatalf("parseV1MemoryLimit = (%d, %v, %v), want limited", limit, limited, ok)
	}
	if _, limited, ok := parseV1MemoryLimit([]byte("9223372036854771712\n")); !ok || limited {
		t.Fatalf("parseV1MemoryLimit(huge) = limited=%v ok=%v, want unlimited ok", limited, ok)
	}
}

func TestParseV1QuotaUS(t *testing.T) {
	if quota, limited, ok := parseV1QuotaUS([]byte("200000\n")); !ok || !limited || quota != 200000 {
		t.Fatalf("parseV1QuotaUS = (%d, %v, %v), want limited 200000", quota, limited, ok)
	}
	if _, limited, ok := parseV1QuotaUS([]byte("-1\n")); !ok || limited {
		t.Fatalf("parseV1QuotaUS(-1) = limited=%v ok=%v, want unlimited ok", limited, ok)
	}
	if _, _, ok := parseV1QuotaUS([]byte("abc\n")); ok {
		t.Fatal("parseV1QuotaUS(abc) should fail")
	}
}

func TestCPUDeltaPercent(t *testing.T) {
	// 1 core-second of usage in a 1s window on a 2-core sandbox = 50%.
	if got := cpuDeltaPercent(0, 1e6, time.Second, 2); got != 50 {
		t.Fatalf("cpuDeltaPercent = %v, want 50", got)
	}
	if got := cpuDeltaPercent(0, 0, time.Second, 2); got != 0 {
		t.Fatalf("cpuDeltaPercent(no usage) = %v, want 0", got)
	}
	if got := cpuDeltaPercent(100, 50, time.Second, 2); got != 0 {
		t.Fatalf("cpuDeltaPercent(regressed counter) = %v, want 0", got)
	}
	if got := cpuDeltaPercent(0, 100, 0, 2); got != 0 {
		t.Fatalf("cpuDeltaPercent(zero wall) = %v, want 0", got)
	}
	if got := cpuDeltaPercent(0, 100, time.Second, 0); got != 0 {
		t.Fatalf("cpuDeltaPercent(zero capacity) = %v, want 0", got)
	}
}
