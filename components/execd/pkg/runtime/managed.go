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

//go:build !windows

package runtime

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// managedProcess wraps an os/exec.Cmd whose lifecycle is driven by the central
// reaper instead of Cmd.Wait(). It owns the child's I/O pipes and delivers the
// exit status from the reaper's wait4 loop.
//
// Callers construct a managedProcess, call Start(), read from stdout/stderr,
// then call Wait() to block until the child exits and clean up resources.
type managedProcess struct {
	Cmd      *exec.Cmd
	pgid     int
	Stdout   io.ReadCloser
	Stderr   io.ReadCloser
	statusCh chan unix.WaitStatus
	waited   bool
	exitCode int
	signal   int
}

// startManagedProcess prepares cmd for managed execution: creates stdout/stderr
// pipes, sets Setpgid, calls cmd.Start(), and registers with the global reaper.
//
// After Start, the caller owns stdout/stderr and must consume them before Wait.
func startManagedProcess(cmd *exec.Cmd) (*managedProcess, error) {
	if cmd == nil {
		return nil, errors.New("managed process: cmd is nil")
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("managed process: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdout.Close()
		return nil, fmt.Errorf("managed process: stderr pipe: %w", err)
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0

	if err := cmd.Start(); err != nil {
		stdout.Close()
		stderr.Close()
		return nil, fmt.Errorf("managed process: start: %w", err)
	}

	mp := &managedProcess{
		Cmd:      cmd,
		pgid:     cmd.Process.Pid,
		Stdout:   stdout,
		Stderr:   stderr,
		statusCh: make(chan unix.WaitStatus, 1),
	}
	globalReaper.register(cmd.Process.Pid, mp.statusCh)
	return mp, nil
}

// startManagedProcessCmd wraps an already-configured *exec.Cmd (Stdout/Stderr
// already set to log files or pipes by the caller) in a managedProcess. It
// ensures Setpgid, calls Start, and registers with the central reaper so that
// Cmd.Wait() is never called — the reaper owns wait4 for this child.
func startManagedProcessCmd(cmd *exec.Cmd) (*managedProcess, error) {
	if cmd == nil {
		return nil, errors.New("managed process: cmd is nil")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("managed process: start: %w", err)
	}

	mp := &managedProcess{
		Cmd:  cmd,
		pgid: cmd.Process.Pid,
	}

	if !globalReaper.isStarted() {
		return mp, nil
	}

	mp.statusCh = make(chan unix.WaitStatus, 1)
	globalReaper.register(cmd.Process.Pid, mp.statusCh)
	return mp, nil
}

// Wait blocks until the child exits (status delivered by the reaper), then
// drains stdout/stderr, joins any copy goroutines, and returns the exit error
// (nil for exit code 0, *exec.ExitError otherwise).
//
// Wait must be called exactly once per managedProcess. After Wait returns,
// stdout/stderr are closed and the reaper registration is released.
func (mp *managedProcess) Wait() error {
	if mp.waited {
		return errors.New("managed process: Wait called more than once")
	}
	mp.waited = true

	if mp.statusCh == nil {
		// Reaper not running (non-init mode): use Cmd.Wait() directly.
		err := mp.Cmd.Wait()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				mp.exitCode = exitErr.ExitCode()
			}
		}
		return err
	}

	defer func() {
		// Don't close pipes while io.Copy goroutines may still be
		// draining. Close after the reaper delivers the status;
		// the write ends were closed by the child's exit.
		if mp.Stdout != nil {
			mp.Stdout.Close()
		}
		if mp.Stderr != nil {
			mp.Stderr.Close()
		}
	}()

	ws := <-mp.statusCh
	globalReaper.deregister(mp.Cmd.Process.Pid)

	mp.exitCode = -1
	if ws.Exited() {
		mp.exitCode = ws.ExitStatus()
		if mp.exitCode != 0 {
			return &exec.ExitError{ProcessState: &os.ProcessState{}}
		}
		return nil
	}
	if ws.Signaled() {
		mp.signal = int(ws.Signal())
		return &exec.ExitError{ProcessState: &os.ProcessState{}}
	}
	return fmt.Errorf("managed process: pid %d unexpected wait status %#x", mp.Cmd.Process.Pid, ws)
}

// ExitCode returns the child's exit code, or -1 if the child was killed by a
// signal or has not yet exited.
func (mp *managedProcess) ExitCode() int {
	return mp.exitCode
}

// Signal sends sig to the process group.
func (mp *managedProcess) Signal(sig syscall.Signal) error {
	return syscall.Kill(-mp.pgid, sig)
}

// Pid returns the child's PID.
func (mp *managedProcess) Pid() int {
	return mp.Cmd.Process.Pid
}

// Pgid returns the child's process group ID.
func (mp *managedProcess) Pgid() int {
	return mp.pgid
}
