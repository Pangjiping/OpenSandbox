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

package isolation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/alibaba/opensandbox/execd/pkg/log"
)

// ErrHardeningDisabled is returned by LaunchWithHardening when hardening is
// not enabled. Callers should treat this as a signal to fall back to a plain
// exec.Command.
var ErrHardeningDisabled = errors.New("hardening: disabled")

// HardeningPolicy carries the pre-exec hardening parameters applied by the
// native launcher before every user-code process.
type HardeningPolicy struct {
	KeepCaps  []string `json:"keep_caps"`
	TargetUID uint32   `json:"target_uid"`
	TargetGID uint32   `json:"target_gid"`
	StripEnv  []string `json:"strip_env"`
}

// execdCredentialEnv lists environment variables that carry execd's own
// credentials and must be stripped from every user-code child.
var execdCredentialEnv = []string{
	"EXECD_ACCESS_TOKEN",
	"JUPYTER_TOKEN",
	"EXECD_ISOLATION_CONFIG",
	"EXECD_ENVS",
	"EXECD_LOG_FILE",
	"EXECD_API_GRACE_SHUTDOWN",
}

// LaunchChild launches cmd through the native launcher with the given
// hardening policy and seccomp filter. The launcher applies credential
// stripping, cap drop, no_new_privs, identity drop, ambient caps, and
// seccomp (in that order) before execve-ing the real command.
//
// launcherPath is the absolute path to the opensandbox-launcher binary.
// seccompBPF is the raw BPF bytecode; nil means skip seccomp.
func LaunchChild(launcherPath string, cmd []string, policy HardeningPolicy, seccompBPF []byte) (*exec.Cmd, error) {
	if launcherPath == "" {
		return nil, fmt.Errorf("launcher: path is empty")
	}
	if len(cmd) == 0 {
		return nil, fmt.Errorf("launcher: no command provided")
	}

	policy.StripEnv = execdCredentialEnv
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("launcher: marshal policy: %w", err)
	}
	policyB64 := base64.StdEncoding.EncodeToString(policyJSON)

	seccompB64 := "none"
	if len(seccompBPF) > 0 {
		seccompB64 = base64.StdEncoding.EncodeToString(seccompBPF)
	}

	argv := []string{launcherPath, "--policy", policyB64, "--seccomp", seccompB64, "--"}
	argv = append(argv, cmd...)

	ecmd := exec.Command(argv[0], argv[1:]...)
	ecmd.Env = os.Environ()
	return ecmd, nil
}

// FindLauncher returns the path to the launcher binary. It first checks the
// directory of the running execd binary, then falls back to a known install
// path.
func FindLauncher() string {
	execdPath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(execdPath)
		candidate := filepath.Join(dir, "opensandbox-launcher")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	const installPath = "/opt/opensandbox/opensandbox-launcher"
	if _, err := os.Stat(installPath); err == nil {
		return installPath
	}
	return ""
}

// Package-level hardening state, initialised by InitLauncher at startup
// and read by launch paths at request time.
var (
	hardeningEnabled bool
	globalLauncher   string
	globalSeccompBPF []byte
	globalKeepCaps   []string
	globalTargetUID  uint32
	globalTargetGID  uint32
)

// InitLauncher initialises the hardening subsystem. It validates config,
// generates seccomp BPF, resolves the launcher binary path, and probes
// capability support. On any failure hardening is marked disabled and the
// reason is logged — the sandbox continues with hardening off (fail-open).
func InitLauncher(cfg Config) error {
	if cfg.Hardening == nil || !cfg.Hardening.Enabled {
		return nil
	}

	if err := ValidateSeccompDeny(cfg.Seccomp); err != nil {
		log.Warn("hardening: seccomp validation failed, hardening disabled: %v", err)
		return nil
	}

	lp := FindLauncher()
	if lp == "" {
		log.Warn("hardening: launcher binary not found (searched: $PWD, /opt/opensandbox/opensandbox-launcher), hardening disabled")
		return nil
	}

	bpf, err := generateSeccompDenyBPF(cfg.Seccomp)
	if err != nil {
		log.Warn("hardening: seccomp BPF generation failed, hardening disabled: %v", err)
		return nil
	}

	// Probe that execd holds the capabilities the launcher needs.
	if !probeLauncherCaps() {
		log.Warn("hardening: execd lacks required capabilities (need CAP_SETPCAP, CAP_SETUID, CAP_SETGID), hardening disabled")
		return nil
	}

	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	hardeningEnabled = true
	globalLauncher = lp
	globalSeccompBPF = bpf
	globalKeepCaps = cfg.Hardening.KeepCapabilities
	globalTargetUID = uid
	globalTargetGID = gid

	log.Info("hardening: enabled launcher=%s target_uid=%d target_gid=%d seccomp=%v keep_caps=%v",
		lp, uid, gid, len(bpf) > 0, globalKeepCaps)
	return nil
}

// HardeningEnabled reports whether the hardening prelude is active.
func HardeningEnabled() bool {
	return hardeningEnabled
}

// LaunchWithHardening wraps args with the native launcher to apply the
// pre-exec hardening prelude. Returns an *exec.Cmd that callers can
// configure (stdout, stderr, env, dir, SysProcAttr) before calling Start.
// When hardening is disabled, returns nil so callers fall back to a plain
// exec.Command.
func LaunchWithHardening(args []string) (*exec.Cmd, error) {
	if !hardeningEnabled {
		return nil, ErrHardeningDisabled
	}
	policy := HardeningPolicy{
		KeepCaps:  globalKeepCaps,
		TargetUID: globalTargetUID,
		TargetGID: globalTargetGID,
	}
	return LaunchChild(globalLauncher, args, policy, globalSeccompBPF)
}

// probeLauncherCaps checks that execd holds the capabilities required by the
// launcher prelude. Returns false (and logs) if any essential cap is missing.
func probeLauncherCaps() bool {
	required := map[string]uintptr{
		"CAP_SETPCAP": 8,
		"CAP_SETUID":  7,
		"CAP_SETGID":  6,
	}
	for name, cv := range required {
		if !hasCap(cv) {
			log.Warn("hardening: missing capability %s (%d)", name, cv)
			return false
		}
	}
	return true
}

// hasCap reports whether the given capability (0–31) is in the current
// process's effective set.
func hasCap(cv uintptr) bool {
	if cv >= 32 {
		return false // not probeable via CapUserData alone
	}
	hdr := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_1,
		Pid:     0,
	}
	var data unix.CapUserData
	if err := unix.Capget(&hdr, &data); err != nil {
		return false
	}
	return data.Effective&(1<<cv) != 0
}
