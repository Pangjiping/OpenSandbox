//go:build linux

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

// Hardening floor (OSEP-0018 §4): when [hardening] is enabled, every
// user-code launch is routed through the opensandbox-launcher native helper,
// which applies the privilege floor between fork and exec (env strip,
// bounding-set trim, no_new_privs, identity drop, ambient caps, seccomp
// last). The launcher's exec syscall (execve) is reserved and rejected at
// config time. Everything is fail-open: a missing prerequisite is reported
// on the capabilities endpoint and the launch proceeds without that layer.
//
// Isolated sessions are exempt from the launcher: their workload is already
// reduced inside the bwrap namespace (bwrap --seccomp + session-gate), and
// applying the floor to the bwrap process itself would deny the unshare/
// setns syscalls and strip the capabilities bwrap needs to build the
// namespace.

package runtime

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/log"
	"golang.org/x/sys/unix"
)

const (
	launcherRuntimePath = "/opt/opensandbox/opensandbox-launcher"

	policyMagic   = 0x4f534258 // "OSBX"
	policyVersion = 1
	flagUIDDrop   = 0x1
	flagCapDrop   = 0x2

	// capSetpcap is the capability number required to trim bounding sets.
	capSetpcap = 8
)

// hardeningPolicy is the serialized policy handed to the launcher over a
// memfd. Field order must stay in sync with struct policy_header in
// native/launcher.c.
type hardeningPolicy struct {
	flags    uint32
	uid      uint32
	gid      uint32
	keepcaps []uint32
	stripEnv []string
	seccomp  []byte
}

type policyHeader struct {
	Magic      uint32
	Version    uint32
	Flags      uint32
	UID        uint32
	GID        uint32
	NKeepCaps  uint32
	NEnv       uint32
	SeccompLen uint32
}

var hardening struct {
	enabled      atomic.Bool
	launcherPath string
	policy       *hardeningPolicy
	capDrop      atomic.Pointer[LayerState]
	seccomp      atomic.Pointer[LayerState]
}

// InitHardening activates the floor from the isolation config. It returns an
// error only for invalid configuration (unknown capability name, or the
// launcher's reserved execve in [seccomp] deny); missing runtime support
// degrades to a reported, non-fatal state.
func InitHardening(cfg isolation.Config) error {
	setLayer := func(dst *atomic.Pointer[LayerState], s LayerState) {
		dst.Store(&s)
	}
	disabled := func(msg string) LayerState {
		return LayerState{State: "disabled", Message: msg}
	}
	degraded := func(msg string) LayerState {
		return LayerState{State: "degraded", Message: msg}
	}
	active := LayerState{State: "active"}

	setLayer(&hardening.capDrop, disabled("hardening not enabled"))
	setLayer(&hardening.seccomp, disabled("hardening not enabled"))

	if cfg.Hardening == nil || !cfg.Hardening.Enabled {
		return nil
	}

	if cfg.Seccomp != nil {
		for _, name := range cfg.Seccomp.Deny {
			if name == "execve" {
				return fmt.Errorf(
					"hardening: [seccomp] deny lists execve, which is reserved for the launcher's final exec; " +
						"use execveat if you need to deny that syscall",
				)
			}
		}
	}

	keepcaps, err := parseKeepCapabilities(cfg.Hardening.KeepCapabilities)
	if err != nil {
		return err
	}

	path := findLauncher()
	if path == "" {
		msg := "opensandbox-launcher not found (searched: /opt/opensandbox/opensandbox-launcher, $PATH)"
		log.Warn("hardening: %s", msg)
		setLayer(&hardening.capDrop, degraded(msg))
		setLayer(&hardening.seccomp, degraded(msg))
		return nil
	}

	seccompBPF, err := isolation.GenerateSeccompDenyBPF(cfg.Seccomp)
	if err != nil {
		return fmt.Errorf("hardening: generate seccomp floor: %w", err)
	}

	hardening.launcherPath = path
	hardening.policy = &hardeningPolicy{
		uid:      uint32(os.Getuid()),
		gid:      uint32(os.Getgid()),
		keepcaps: keepcaps,
		stripEnv: isolation.ExecdConfigEnvBlacklist(),
		seccomp:  seccompBPF,
	}
	// The identity drop is only meaningful when execd is root (a non-root
	// execd already runs as the image's user).
	if os.Geteuid() == 0 {
		hardening.policy.flags |= flagUIDDrop
	}
	hardening.policy.flags |= flagCapDrop

	hasSetpcap := effectiveCapsHave(capSetpcap)
	if hasSetpcap {
		setLayer(&hardening.capDrop, active)
	} else {
		msg := "cap_drop skipped: execd lacks CAP_SETPCAP (bounding-set trim impossible); seccomp/identity still apply"
		log.Warn("hardening: %s", msg)
		setLayer(&hardening.capDrop, degraded(msg))
	}
	if len(seccompBPF) == 0 {
		msg := "seccomp floor skipped: deny list is empty"
		log.Warn("hardening: %s", msg)
		setLayer(&hardening.seccomp, degraded(msg))
	} else {
		setLayer(&hardening.seccomp, active)
	}

	hardening.enabled.Store(true)
	log.Info("hardening: enabled (launcher=%s uid=%d gid=%d keep_caps=%v seccomp=%d bytes)",
		path, hardening.policy.uid, hardening.policy.gid,
		cfg.Hardening.KeepCapabilities, len(seccompBPF))
	return nil
}

var launcherSearchPaths = []string{launcherRuntimePath}

func findLauncher() string {
	if path, err := exec.LookPath("opensandbox-launcher"); err == nil {
		return path
	}
	for _, p := range launcherSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func effectiveCapsHave(cap uint32) bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		return value&(1<<cap) != 0
	}
	return false
}

var capNameToNumber = map[string]uint32{
	"CAP_CHOWN": 0, "CAP_DAC_OVERRIDE": 1, "CAP_DAC_READ_SEARCH": 2,
	"CAP_FOWNER": 3, "CAP_FSETID": 4, "CAP_KILL": 5, "CAP_SETGID": 6,
	"CAP_SETUID": 7, "CAP_SETPCAP": 8, "CAP_LINUX_IMMUTABLE": 9,
	"CAP_NET_BIND_SERVICE": 10, "CAP_NET_BROADCAST": 11, "CAP_NET_ADMIN": 12,
	"CAP_NET_RAW": 13, "CAP_IPC_LOCK": 14, "CAP_IPC_OWNER": 15,
	"CAP_SYS_MODULE": 16, "CAP_SYS_RAWIO": 17, "CAP_SYS_CHROOT": 18,
	"CAP_SYS_PTRACE": 19, "CAP_SYS_PACCT": 20, "CAP_SYS_ADMIN": 21,
	"CAP_SYS_BOOT": 22, "CAP_SYS_NICE": 23, "CAP_SYS_RESOURCE": 24,
	"CAP_SYS_TIME": 25, "CAP_SYS_TTY_CONFIG": 26, "CAP_MKNOD": 27,
	"CAP_LEASE": 28, "CAP_AUDIT_WRITE": 29, "CAP_AUDIT_CONTROL": 30,
	"CAP_SETFCAP": 31, "CAP_MAC_OVERRIDE": 32, "CAP_MAC_ADMIN": 33,
	"CAP_SYSLOG": 34, "CAP_WAKE_ALARM": 35, "CAP_BLOCK_SUSPEND": 36,
	"CAP_AUDIT_READ": 37, "CAP_PERFMON": 38, "CAP_BPF": 39,
	"CAP_CHECKPOINT_RESTORE": 40,
}

func parseKeepCapabilities(names []string) ([]uint32, error) {
	var caps []uint32
	for _, name := range names {
		num, ok := capNameToNumber[name]
		if !ok {
			return nil, fmt.Errorf("hardening: unknown capability %q in keep_capabilities", name)
		}
		caps = append(caps, num)
	}
	return caps, nil
}

// hardenCmd rewrites cmd to exec the launcher with the floor policy, unless
// the launch opted out (isolated sessions).
func hardenCmd(cmd *exec.Cmd, noHardening bool) error {
	if noHardening || !hardening.enabled.Load() {
		return nil
	}
	policy, err := encodePolicy(hardening.policy)
	if err != nil {
		return fmt.Errorf("hardening: encode policy: %w", err)
	}
	fd, err := createPolicyMemfd(policy)
	if err != nil {
		return fmt.Errorf("hardening: policy memfd: %w", err)
	}
	file := os.NewFile(uintptr(fd), "launcher-policy")
	childFd := strconv.Itoa(3 + len(cmd.ExtraFiles))
	cmd.ExtraFiles = append(cmd.ExtraFiles, file)

	originalArgs := cmd.Args
	cmd.Path = hardening.launcherPath
	cmd.Args = append([]string{hardening.launcherPath, childFd, "--"}, originalArgs...)
	return nil
}

func encodePolicy(p *hardeningPolicy) ([]byte, error) {
	for _, name := range p.stripEnv {
		if len(name) == 0 || len(name) >= 64 || strings.ContainsRune(name, '\x00') {
			return nil, fmt.Errorf("invalid env-strip name %q", name)
		}
	}
	buf := new(bytes.Buffer)
	hdr := policyHeader{
		Magic:      policyMagic,
		Version:    policyVersion,
		Flags:      p.flags,
		UID:        p.uid,
		GID:        p.gid,
		NKeepCaps:  uint32(len(p.keepcaps)),
		NEnv:       uint32(len(p.stripEnv)),
		SeccompLen: uint32(len(p.seccomp)),
	}
	if err := binary.Write(buf, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	for _, capNum := range p.keepcaps {
		if err := binary.Write(buf, binary.LittleEndian, capNum); err != nil {
			return nil, err
		}
	}
	for _, name := range p.stripEnv {
		buf.WriteString(name)
		buf.WriteByte(0)
	}
	buf.Write(p.seccomp)
	return buf.Bytes(), nil
}

func createPolicyMemfd(policy []byte) (int, error) {
	fd, err := unix.MemfdCreate("launcher-policy", 0)
	if err != nil {
		return -1, fmt.Errorf("memfd_create: %w", err)
	}
	if _, err := unix.Write(fd, policy); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("write launcher policy: %w", err)
	}
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("seek launcher policy: %w", err)
	}
	return fd, nil
}

// HardeningReport returns the current hardening enforcement state for the
// capabilities endpoint.
func ReportHardening() HardeningReport {
	mode, shield := InitModeReport()
	report := HardeningReport{
		InitMode:     mode,
		SignalShield: shield,
		CapDrop:      LayerState{State: "disabled", Message: "hardening not enabled"},
		Seccomp:      LayerState{State: "disabled", Message: "hardening not enabled"},
		Landlock: LayerState{
			State:   "disabled",
			Message: "landlock confinement is not enabled (phase 3)",
		},
		Ebpf: LayerState{
			State:   "disabled",
			Message: "eBPF observation is not enabled (phase 4)",
		},
	}
	if cs := hardening.capDrop.Load(); cs != nil {
		report.CapDrop = *cs
	}
	if ss := hardening.seccomp.Load(); ss != nil {
		report.Seccomp = *ss
	}
	return report
}
