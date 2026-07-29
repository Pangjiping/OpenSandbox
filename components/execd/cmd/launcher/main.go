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

//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type launcherPolicy struct {
	KeepCaps  []string `json:"keep_caps"`
	TargetUID uint32   `json:"target_uid"`
	TargetGID uint32   `json:"target_gid"`
	StripEnv  []string `json:"strip_env"`
}

func main() {
	var (
		policyB64  string
		seccompB64 string
	)
	flag.StringVar(&policyB64, "policy", "", "base64-encoded hardening policy JSON")
	flag.StringVar(&seccompB64, "seccomp", "", "base64-encoded seccomp BPF (or 'none')")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "launcher: no command provided")
		os.Exit(125)
	}

	policy, err := decodePolicy(policyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "launcher: policy: %v\n", err)
		os.Exit(125)
	}

	bpf, err := decodeSeccomp(seccompB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "launcher: seccomp: %v\n", err)
		os.Exit(125)
	}

	if err := applyHardening(policy, bpf); err != nil {
		fmt.Fprintf(os.Stderr, "launcher: %v\n", err)
		os.Exit(125)
	}

	argv0, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "launcher: %s: %v\n", args[0], err)
		os.Exit(126)
	}

	if err := syscall.Exec(argv0, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "launcher: exec %s: %v\n", argv0, err)
		os.Exit(126)
	}
}

func decodePolicy(b64 string) (*launcherPolicy, error) {
	if b64 == "" {
		return &launcherPolicy{}, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	p := &launcherPolicy{}
	if err := json.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return p, nil
}

func decodeSeccomp(b64 string) ([]byte, error) {
	if b64 == "" || b64 == "none" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return raw, nil
}

func applyHardening(p *launcherPolicy, bpf []byte) error {
	// Step 0: strip credential env vars.
	for _, key := range p.StripEnv {
		_ = os.Unsetenv(key)
	}

	// Step 1: keep capabilities across UID change.
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_KEEPCAPS: %w", err)
	}

	// Step 2: trim bounding set for caps not in KeepCaps.
	if err := dropBoundingCaps(p.KeepCaps); err != nil {
		return fmt.Errorf("trim bounding set: %w", err)
	}

	// Step 3: no_new_privs.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// Step 4: drop identity.
	if err := dropIdentity(p.TargetUID, p.TargetGID); err != nil {
		return fmt.Errorf("drop identity: %w", err)
	}

	// Step 5: set ambient capabilities.
	if err := raiseAmbientCaps(p.KeepCaps); err != nil {
		return fmt.Errorf("ambient caps: %w", err)
	}

	// Step 6: seccomp (LAST — never blocks launcher's own setup calls).
	if len(bpf) > 0 {
		if err := installSeccomp(bpf); err != nil {
			return fmt.Errorf("seccomp: %w", err)
		}
	}

	return nil
}

func dropBoundingCaps(keep []string) error {
	keepSet := make(map[string]struct{}, len(keep))
	for _, c := range keep {
		keepSet[c] = struct{}{}
	}
	for name, cv := range capNameToValue {
		if _, ok := keepSet[name]; ok {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(cv), 0, 0, 0); err != nil {
			if err == unix.EINVAL {
				continue // cap not in bounding set
			}
			return err
		}
	}
	return nil
}

func dropIdentity(uid, gid uint32) error {
	if err := syscall.Setgroups(nil); err != nil {
		return err
	}
	if err := syscall.Setgid(int(gid)); err != nil {
		return err
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return err
	}
	return nil
}

func raiseAmbientCaps(keep []string) error {
	for _, name := range keep {
		cv, ok := capNameToValue[name]
		if !ok {
			continue
		}

		caps := unix.CapUserHeader{
			Version: unix.LINUX_CAPABILITY_VERSION_3,
			Pid:     0,
		}
		var data capUserV3
		if err := capgetV3(&caps, &data); err != nil {
			return fmt.Errorf("capget: %w", err)
		}
		setCapBitV3(&data, cv)
		if err := capsetV3(&caps, &data); err != nil {
			return fmt.Errorf("capset %s: %w", name, err)
		}

		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(cv), 0, 0); err != nil {
			return fmt.Errorf("ambient raise %s: %w", name, err)
		}
	}
	return nil
}

func capgetV3(hdr *unix.CapUserHeader, data *capUserV3) error {
	_, _, e1 := unix.Syscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(hdr)), uintptr(unsafe.Pointer(data)), 0)
	if e1 != 0 {
		return e1
	}
	return nil
}

func capsetV3(hdr *unix.CapUserHeader, data *capUserV3) error {
	_, _, e1 := unix.Syscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(hdr)), uintptr(unsafe.Pointer(data)), 0)
	if e1 != 0 {
		return e1
	}
	atomic.StoreUint32(&hdr.Version, unix.LINUX_CAPABILITY_VERSION_3)
	return nil
}

// capUserV3 mirrors the kernel v3 capability layout: an array of two
// records, each {effective, permitted, inheritable}. Caps 0–31 are in
// record [0]; caps 32–63 in record [1].
type capUserV3 [2]struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

func setCapBitV3(v3 *capUserV3, cv uintptr) {
	idx := 0
	if cv >= 32 {
		idx = 1
		cv -= 32
	}
	bit := uint32(1) << cv
	v3[idx].Effective |= bit
	v3[idx].Permitted |= bit
	v3[idx].Inheritable |= bit
}

func installSeccomp(bpf []byte) error {
	n := len(bpf) / 8
	filters := make([]unix.SockFilter, n)
	for i := range n {
		off := i * 8
		filters[i] = unix.SockFilter{
			Code: uint16(bpf[off]) | uint16(bpf[off+1])<<8,
			Jt:   bpf[off+2],
			Jf:   bpf[off+3],
			K:    uint32(bpf[off+4]) | uint32(bpf[off+5])<<8 | uint32(bpf[off+6])<<16 | uint32(bpf[off+7])<<24,
		}
	}
	prog := unix.SockFprog{
		Len:    uint16(n),
		Filter: &filters[0],
	}
	return unix.Prctl(
		unix.PR_SET_SECCOMP,
		unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&prog)),
		0,
		0,
	)
}

// capNameToValue maps capability string names (as used in the isolation TOML
// and seccomp_gen.go) to their numeric values. Linux capability values are
// stable ABI; this table is the authoritative mapping for the subset that
// operators may want to retain via KeepCaps.
var capNameToValue = map[string]uintptr{
	"CAP_CHOWN":              0,
	"CAP_DAC_OVERRIDE":       1,
	"CAP_DAC_READ_SEARCH":    2,
	"CAP_FOWNER":             3,
	"CAP_FSETID":             4,
	"CAP_KILL":               5,
	"CAP_SETGID":             6,
	"CAP_SETUID":             7,
	"CAP_SETPCAP":            8,
	"CAP_LINUX_IMMUTABLE":    9,
	"CAP_NET_BIND_SERVICE":   10,
	"CAP_NET_BROADCAST":      11,
	"CAP_NET_ADMIN":          12,
	"CAP_NET_RAW":            13,
	"CAP_IPC_LOCK":           14,
	"CAP_IPC_OWNER":          15,
	"CAP_SYS_MODULE":         16,
	"CAP_SYS_RAWIO":          17,
	"CAP_SYS_CHROOT":         18,
	"CAP_SYS_PTRACE":         19,
	"CAP_SYS_PACCT":          20,
	"CAP_SYS_ADMIN":          21,
	"CAP_SYS_BOOT":           22,
	"CAP_SYS_NICE":           23,
	"CAP_SYS_RESOURCE":       24,
	"CAP_SYS_TIME":           25,
	"CAP_SYS_TTY_CONFIG":     26,
	"CAP_MKNOD":              27,
	"CAP_LEASE":              28,
	"CAP_AUDIT_WRITE":        29,
	"CAP_AUDIT_CONTROL":      30,
	"CAP_SETFCAP":            31,
	"CAP_MAC_OVERRIDE":       32,
	"CAP_MAC_ADMIN":          33,
	"CAP_SYSLOG":             34,
	"CAP_WAKE_ALARM":         35,
	"CAP_BLOCK_SUSPEND":      36,
	"CAP_AUDIT_READ":         37,
	"CAP_PERFMON":            38,
	"CAP_BPF":                39,
	"CAP_CHECKPOINT_RESTORE": 40,
}

// allCaps lists every known capability name for bounding-set drop. Every cap
// is dropped unless explicitly listed in KeepCaps.
var allCaps []string

func init() {
	for name := range capNameToValue {
		allCaps = append(allCaps, name)
	}
}
