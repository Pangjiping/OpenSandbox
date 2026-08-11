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

package runtime

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
)

var (
	launcherOnce  sync.Once
	launcherBuilt string
	launcherErr   error
)

func buildLauncher(t *testing.T) string {
	t.Helper()
	launcherOnce.Do(func() {
		cc, err := exec.LookPath("cc")
		if err != nil {
			launcherErr = err
			return
		}
		dir, err := os.MkdirTemp("", "launcher-test-*")
		if err != nil {
			launcherErr = err
			return
		}
		launcherBuilt = filepath.Join(dir, "opensandbox-launcher")
		src := filepath.Join("..", "..", "native", "launcher.c")
		cmd := exec.Command(cc, "-O2", "-Wall", "-Wextra", "-Werror",
			"-o", launcherBuilt, src)
		if out, err := cmd.CombinedOutput(); err != nil {
			launcherErr = err
			t.Logf("launcher build output: %s", out)
		}
	})
	if launcherErr != nil {
		t.Skipf("cannot build opensandbox-launcher: %v", launcherErr)
	}
	return launcherBuilt
}

func resetHardening() {
	hardening.enabled.Store(false)
	hardening.launcherPath = ""
	hardening.policy = nil
	hardening.capDrop.Store(nil)
	hardening.seccomp.Store(nil)
	launcherSearchPaths = []string{launcherRuntimePath}
}

func initHardeningForTest(t *testing.T, cfg isolation.Config) {
	t.Helper()
	t.Cleanup(resetHardening)
	if err := InitHardening(cfg); err != nil {
		t.Fatalf("InitHardening: %v", err)
	}
}

func hardenedCfg(keepCaps ...string) isolation.Config {
	return isolation.Config{
		Hardening: &isolation.HardeningConfig{
			Enabled:          true,
			KeepCapabilities: keepCaps,
		},
	}
}

// childStatus launches a command through the floor and returns its combined
// output. The command may exit non-zero (e.g. a seccomp-denied syscall);
// assertions run against the output.
func childStatus(t *testing.T, cfg isolation.Config, script string) string {
	t.Helper()
	initHardeningForTest(t, cfg)
	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", script)
	cmd.Stdout = &out
	cmd.Stderr = &out
	mp, err := launchManaged(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := mp.Wait(); err != nil {
		t.Logf("command exited with error: %v", err)
	}
	return out.String()
}

func TestHardeningDisabledByDefault(t *testing.T) {
	initHardeningForTest(t, isolation.Config{})
	report := ReportHardening()
	if report.CapDrop.State != "disabled" || report.Seccomp.State != "disabled" {
		t.Fatalf("hardening states = %q/%q, want disabled/disabled",
			report.CapDrop.State, report.Seccomp.State)
	}
	out := childStatus(t, isolation.Config{}, "echo hi")
	if out != "hi\n" {
		t.Fatalf("output = %q, want hi (launch must be unmodified)", out)
	}
}

func TestHardeningAppliesFloor(t *testing.T) {
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)
	out := childStatus(t, hardenedCfg(), `grep -E "^CapEff:|^CapPrm:|^NoNewPrivs:|^Uid:" /proc/self/status`)
	if !strings.Contains(out, "NoNewPrivs:	1") {
		t.Fatalf("NoNewPrivs not set: %q", out)
	}
	if strings.Contains(out, "CapEff:	0000000000000000") || os.Geteuid() != 0 {
		return
	}
	t.Fatalf("CapEff not dropped to zero: %q", out)
}

func TestHardeningKeepsExecdPrivileges(t *testing.T) {
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)

	before, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	out := childStatus(t, hardenedCfg(), "true")
	after, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	capOf := func(status []byte) string {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				return line
			}
		}
		return ""
	}
	if capOf(before) != capOf(after) {
		t.Fatalf("execd CapEff changed across a hardened launch:\n before=%s\n after =%s\n child=%q",
			capOf(before), capOf(after), out)
	}
}

func TestHardeningSeccompBlocksDeniedSyscall(t *testing.T) {
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)
	// The filter is installed (Seccomp: 2 = SECCOMP_MODE_FILTER) before the
	// workload execs; a behavioral probe is unreliable because the container
	// runtime's own seccomp profile already blocks syscalls like mount.
	out := childStatus(t, hardenedCfg(), `grep "^Seccomp:" /proc/self/status`)
	if !strings.Contains(out, "Seccomp:	2") {
		t.Fatalf("seccomp filter not active in the child: %q", out)
	}
}

func TestHardeningEnvStrip(t *testing.T) {
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)
	initHardeningForTest(t, hardenedCfg())

	var out bytes.Buffer
	cmd := exec.Command("sh", "-c", "env")
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = append(os.Environ(),
		"EXECD_ACCESS_TOKEN=supersecret",
		"JUPYTER_TOKEN=anothersecret",
	)
	mp, err := launchManaged(cmd)
	if err != nil {
		t.Fatal(err)
	}
	_ = mp.Wait()
	for _, secret := range []string{"supersecret", "anothersecret"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("execd credential env leaked into the workload: %q", out.String())
		}
	}
}

func TestHardeningKeepCapabilities(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to raise capabilities")
	}
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)
	out := childStatus(t, hardenedCfg("CAP_NET_RAW"), `grep "^CapEff:" /proc/self/status`)
	// CAP_NET_RAW = 13 → 0x2000.
	if !strings.Contains(out, "CapEff:	0000000000002000") {
		t.Fatalf("kept capability not raised: %q", out)
	}
}

func TestHardeningRejectsReservedExecve(t *testing.T) {
	cfg := isolation.Config{
		Seccomp: &isolation.SeccompOverride{Deny: []string{"execve", "mount"}},
		Hardening: &isolation.HardeningConfig{
			Enabled: true,
		},
	}
	if err := InitHardening(cfg); err == nil || !strings.Contains(err.Error(), "execve") {
		t.Fatalf("InitHardening error = %v, want execve rejection", err)
	}
	resetHardening()
}

func TestHardeningRejectsUnknownCapability(t *testing.T) {
	cfg := isolation.Config{
		Hardening: &isolation.HardeningConfig{
			Enabled:          true,
			KeepCapabilities: []string{"CAP_DOES_NOT_EXIST"},
		},
	}
	if err := InitHardening(cfg); err == nil {
		t.Fatal("InitHardening error = nil, want unknown capability rejection")
	}
	resetHardening()
}

func TestHardeningDegradesWhenLauncherMissing(t *testing.T) {
	launcherSearchPaths = nil
	initHardeningForTest(t, hardenedCfg())
	report := ReportHardening()
	if report.CapDrop.State != "degraded" || report.Seccomp.State != "degraded" {
		t.Fatalf("states = %q/%q, want degraded/degraded",
			report.CapDrop.State, report.Seccomp.State)
	}
	// Fail-open: the launch still works without the floor.
	out := childStatus(t, hardenedCfg(), "echo still-works")
	if out != "still-works\n" {
		t.Fatalf("output = %q, want still-works", out)
	}
}

func TestHardeningReportLayers(t *testing.T) {
	buildLauncher(t)
	launcherSearchPaths = append(launcherSearchPaths, launcherBuilt)
	initHardeningForTest(t, hardenedCfg())
	report := ReportHardening()
	if report.Landlock.State != "disabled" || report.Ebpf.State != "disabled" {
		t.Fatalf("future layers = %q/%q, want disabled/disabled",
			report.Landlock.State, report.Ebpf.State)
	}
	if report.CapDrop.State != "active" && report.CapDrop.State != "degraded" {
		t.Fatalf("cap_drop state = %q, want active or degraded (root)", report.CapDrop.State)
	}
	if report.Seccomp.State != "active" {
		t.Fatalf("seccomp state = %q, want active", report.Seccomp.State)
	}
}
