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

package runtime

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/log"
)

// entrypointSignals lists the signals that execd forwards to the entrypoint
// process group when running as the sandbox init (PID 1).
var entrypointSignals = []os.Signal{
	syscall.SIGTERM,
	syscall.SIGHUP,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
	syscall.SIGWINCH,
}

const (
	shutdownGracePeriod = 5 * time.Second
)

// RunInit is the init-mode main loop. It starts the HTTP server in a
// background goroutine, then launches the user entrypoint as a managed child.
// It reaps orphans, forwards signals, and exits with the entrypoint's exit
// code when the entrypoint finishes.
//
// The server listens on the given addr. If addr is empty, the server is
// skipped (useful for smoke tests that just need the init loop).
//
// args are the user command and its arguments (after -- on the execd command
// line). If args is empty, no entrypoint is launched and execd exits 0.
func RunInit(engine interface{ RunListener(net.Listener) error }, addr string, args []string) {
	initMode := "subreaper"
	if os.Getpid() == 1 {
		initMode = "pid1"
	}
	log.Info("execd init: mode=%s pid=%d", initMode, os.Getpid())

	if os.Getpid() != 1 {
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			log.Warn("execd init: PR_SET_CHILD_SUBREAPER failed (proceeding): %v", err)
		}
	}

	StartReaper()

	if addr != "" {
		listener, err := net.Listen("tcp4", addr)
		if err != nil {
			log.Error("execd init: listen on %s: %v", addr, err)
			os.Exit(1)
		}
		log.Info("execd init: listening on %s (IPv4)", addr)
		go func() {
			if err := engine.RunListener(listener); err != nil {
				log.Error("execd init: server: %v", err)
			}
		}()
	}

	if len(args) == 0 {
		log.Info("execd init: no entrypoint args provided, exiting")
		os.Exit(0)
	}

	mp, err := startEntrypoint(args)
	if err != nil {
		log.Error("execd init: failed to start entrypoint: %v", err)
		os.Exit(1)
	}

	forwardSignalsToEntrypoint(mp)

	err = mp.Wait()
	exitCode := exitCodeFromError(err, mp)
	log.Info("execd init: entrypoint pid=%d exited code=%d", mp.Pid(), exitCode)

	stopOtherChildren(mp)

	os.Exit(exitCode)
}

// startEntrypoint launches the user command as a managedProcess. The command is
// run via the preferred shell (bash or sh) to match the original bootstrap.sh
// behaviour. When hardening is enabled, the command is routed through the
// native launcher for pre-exec privilege reduction.
func startEntrypoint(args []string) (*managedProcess, error) {
	shell, shellArgs := shellCommand(args...)
	var cmd *exec.Cmd
	hcmd, err := isolation.LaunchWithHardening(append([]string{shell}, shellArgs...))
	if err != nil && !errors.Is(err, isolation.ErrHardeningDisabled) {
		return nil, fmt.Errorf("hardening launch: %w", err)
	}
	if hcmd != nil {
		cmd = hcmd
	} else {
		cmd = exec.Command(shell, shellArgs...)
	}
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return startManagedProcessCmd(cmd)
}

// forwardSignalsToEntrypoint listens for application signals and forwards them
// to the entrypoint's process group. SIGTERM from outside the PID namespace
// (container stop) is forwarded so the workload can shut down gracefully.
// In-namespace SIGTERM (workload kill 1) is ignored by the kernel PID 1 signal
// shield; no handler is installed for it.
func forwardSignalsToEntrypoint(mp *managedProcess) {
	sigCh := make(chan os.Signal, len(entrypointSignals))
	signal.Notify(sigCh, entrypointSignals...)
	go func() {
		for sig := range sigCh {
			if sig == nil {
				continue
			}
			s := sig.(syscall.Signal)
			if s == syscall.SIGCHLD || s == syscall.SIGURG {
				continue
			}
			log.Info("execd init: forwarding signal %s to entrypoint pgid=%d", s, mp.Pgid())
			_ = mp.Signal(s)
		}
	}()
}

// stopOtherChildren sends SIGTERM to the entrypoint's process group, waits
// for the grace period, then escalates to SIGKILL. Called after the entrypoint
// has exited to clean up the sandbox before execd exits.
//
// In PID 1 mode the kernel signal shield protects execd, so we can broadcast
// safely. In subreaper mode we only signal the entrypoint's process group to
// avoid affecting unrelated processes.
func stopOtherChildren(mp *managedProcess) {
	log.Info("execd init: stopping children (grace=%s, mode=%s)", shutdownGracePeriod, modeStr())
	if os.Getpid() == 1 {
		_ = syscall.Kill(-1, syscall.SIGTERM)
	} else {
		_ = mp.Signal(syscall.SIGTERM)
	}
	time.Sleep(shutdownGracePeriod)
	if os.Getpid() == 1 {
		_ = syscall.Kill(-1, syscall.SIGKILL)
	} else {
		_ = mp.Signal(syscall.SIGKILL)
	}
}

func modeStr() string {
	if os.Getpid() == 1 {
		return "pid1"
	}
	return "subreaper"
}

func exitCodeFromError(err error, mp *managedProcess) int {
	if err == nil {
		return 0
	}
	if mp.ExitCode() >= 0 {
		return mp.ExitCode()
	}
	// Killed by signal: 128 + signal number (convention).
	if mp.signal > 0 {
		return 128 + mp.signal
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}
