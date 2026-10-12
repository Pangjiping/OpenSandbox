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
	"math"
	"slices"
	"strconv"
	"strings"
)

// procCgroupEntry is one line of /proc/self/cgroup.
type procCgroupEntry struct {
	controllers []string // v1 controller names; empty for the "0::" v2 line
	path        string
}

// parseCgroupEntries parses /proc/self/cgroup lines of the form
// "hierarchy:controllers:path".
func parseCgroupEntries(data []byte) []procCgroupEntry {
	var entries []procCgroupEntry
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 || parts[2] == "" {
			continue
		}
		entry := procCgroupEntry{path: parts[2]}
		if parts[1] != "" {
			for _, name := range strings.Split(parts[1], ",") {
				if name != "" {
					entry.controllers = append(entry.controllers, name)
				}
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// cgroupV2RelPath returns the sandbox's unified-hierarchy path. Hybrid hosts
// (v1 controllers alongside a unified hierarchy) return "": there the "0::"
// entry is degenerate — memory accounting lives on the v1 hierarchy, and
// reading the unified path would attribute the wrong scope.
func cgroupV2RelPath(entries []procCgroupEntry) string {
	for _, entry := range entries {
		if slices.Contains(entry.controllers, "memory") {
			return ""
		}
	}
	for _, entry := range entries {
		if len(entry.controllers) == 0 {
			return entry.path
		}
	}
	return ""
}

// cgroupV1RelPath returns the v1 hierarchy path of the first entry whose
// controller list contains any of the given names.
func cgroupV1RelPath(entries []procCgroupEntry, names ...string) string {
	for _, entry := range entries {
		if len(entry.controllers) == 0 {
			continue
		}
		for _, name := range names {
			if slices.Contains(entry.controllers, name) {
				return entry.path
			}
		}
	}
	return ""
}

// parseCPUStatUsageUSec extracts usage_usec from a cgroup v2 cpu.stat.
func parseCPUStatUsageUSec(data []byte) (uint64, bool) {
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "usage_usec" {
			value, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return 0, false
			}
			return value, true
		}
	}
	return 0, false
}

// parseSingleUint parses a file holding one unsigned integer, e.g. the
// nanoseconds counter of cgroup v1 cpuacct.usage.
func parseSingleUint(data []byte) (uint64, bool) {
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// parseSingleInt parses a file holding one signed integer.
func parseSingleInt(data []byte) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// parseCPUMax parses cgroup v2 cpu.max: "<quota|max> <period>".
func parseCPUMax(data []byte) (quotaUSec, periodUSec int64, limited bool, ok bool) {
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, false, false
	}
	period, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || period <= 0 {
		return 0, 0, false, false
	}
	if fields[0] == "max" {
		return 0, period, false, true
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, 0, false, false
	}
	return quota, period, true, true
}

// quotaCores converts a CPU quota (quota/period microseconds) into a core
// count, rounding up to whole cores.
func quotaCores(quotaUSec, periodUSec int64) float64 {
	if quotaUSec <= 0 || periodUSec <= 0 {
		return 0
	}
	return math.Ceil(float64(quotaUSec) / float64(periodUSec))
}

// parseMemoryMax parses cgroup v2 memory.max: a byte count or "max"
// (unlimited).
func parseMemoryMax(data []byte) (limit int64, limited bool, ok bool) {
	if strings.TrimSpace(string(data)) == "max" {
		return 0, false, true
	}
	value, ok := parseSingleInt(data)
	if !ok {
		return 0, false, false
	}
	return value, true, true
}

// v1UnlimitedBytes: cgroup v1 encodes "no limit" as a huge byte count
// instead of a marker word.
const v1UnlimitedBytes = 1 << 50

// parseV1MemoryLimit parses cgroup v1 memory.limit_in_bytes.
func parseV1MemoryLimit(data []byte) (limit int64, limited bool, ok bool) {
	value, ok := parseSingleInt(data)
	if !ok {
		return 0, false, false
	}
	if value >= v1UnlimitedBytes {
		return 0, false, true
	}
	return value, true, true
}

// parseV1QuotaUS parses cgroup v1 cpu.cfs_quota_us (<= 0 means unlimited).
func parseV1QuotaUS(data []byte) (quotaUSec int64, limited bool, ok bool) {
	value, ok := parseSingleInt(data)
	if !ok {
		return 0, false, false
	}
	if value <= 0 {
		return 0, false, true
	}
	return value, true, true
}
