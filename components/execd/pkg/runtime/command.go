// Copyright 2025 Alibaba Group Holding Ltd.
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
// +build !windows

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/alibaba/opensandbox/internal/safego"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/jupyter/execute"
	"github.com/alibaba/opensandbox/execd/pkg/log"
	"github.com/alibaba/opensandbox/execd/pkg/util/pathutil"
)

const bashShell = "bash"

var forwardSignals = []os.Signal{
	syscall.SIGINT,
	syscall.SIGTERM,
	syscall.SIGHUP,
	syscall.SIGQUIT,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
	syscall.SIGWINCH,
}

// getShell returns "bash" if available, otherwise "sh". The result is cached
// for the process lifetime; tests that mutate PATH must call
// resetShellCacheForTest.
var (
	shellCacheOnce sync.Once
	shellCacheVal  string
)

func getShell() string {
	shellCacheOnce.Do(func() {
		if _, err := exec.LookPath(bashShell); err == nil {
			shellCacheVal = bashShell
		} else {
			shellCacheVal = "sh"
		}
	})
	return shellCacheVal
}

// shellCommand returns (shell, argv) for launching the preferred shell,
// prepending --noprofile --norc when Bash is selected. Extra positional
// arguments (script path, or "-c" + code) are appended after.
func shellCommand(extra ...string) (string, []string) {
	shell := getShell()
	args := make([]string, 0, 2+len(extra))
	if shell == bashShell {
		args = append(args, "--noprofile", "--norc")
	}
	args = append(args, extra...)
	return shell, args
}

func buildCredential(uid, gid *uint32) (*syscall.Credential, error) {
	if uid == nil && gid == nil {
		return nil, nil //nolint:nilnil
	}

	cred := &syscall.Credential{}
	if uid != nil {
		cred.Uid = *uid
		// Load user info to get primary GID and supplemental groups
		u, err := user.LookupId(strconv.FormatUint(uint64(*uid), 10))
		if err == nil {
			// Set primary GID if not explicitly provided
			if gid == nil {
				primaryGid, err := strconv.ParseUint(u.Gid, 10, 32)
				if err == nil {
					cred.Gid = uint32(primaryGid)
				}
			}

			// Load supplemental groups
			gids, err := u.GroupIds()
			if err == nil {
				for _, g := range gids {
					id, err := strconv.ParseUint(g, 10, 32)
					if err == nil {
						cred.Groups = append(cred.Groups, uint32(id))
					}
				}
			}
		}
	}

	// Override Gid if explicitly provided
	if gid != nil {
		cred.Gid = *gid
	}

	return cred, nil
}

// runCommand executes shell commands and streams their output.
//
//nolint:gocognit
func (c *Controller) runCommand(ctx context.Context, request *ExecuteCodeRequest) error {
	session := c.newContextID()

	signals := make(chan os.Signal, len(forwardSignals)+1)
	defer close(signals)
	signal.Notify(signals, forwardSignals...)
	defer signal.Stop(signals)

	stdout, stderr, err := c.stdLogDescriptor(session)
	if err != nil {
		return fmt.Errorf("failed to get stdlog descriptor: %w", err)
	}
	defer stdout.Close()
	defer stderr.Close()
	stdoutPath := c.stdoutFileName(session)
	stderrPath := c.stderrFileName(session)

	startAt := time.Now()
	log.Info("received command: %v", log.SanitizeCommand(request.Code))
	// --noprofile/--norc are no-ops for `bash -c`, so shellCommand is not used here.
	shell := getShell()

	cmd, err := maybeHardenedCommand(shell, "-c", request.Code)
	if err != nil {
		return err
	}
	extraEnv := mergeExtraEnvs(loadExtraEnvFromFile(), request.Envs)
	cwd, err := pathutil.ExpandPathWithEnv(request.Cwd, extraEnv)
	if err != nil {
		return fmt.Errorf("resolve request cwd %s: %w", request.Cwd, err)
	}

	// Configure credentials and process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	if !isolation.HardeningEnabled() {
		cred, err := buildCredential(request.Uid, request.Gid)
		if err != nil {
			return fmt.Errorf("failed to build credential: %w", err)
		}
		cmd.SysProcAttr.Credential = cred
	}

	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if isolation.HardeningEnabled() {
		cmd.Env = mergeEnvs(cmd.Env, extraEnv)
	} else {
		cmd.Env = mergeEnvs(os.Environ(), extraEnv)
	}
	cmd.Dir = cwd

	done := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(2)
	safego.Go(func() {
		defer wg.Done()
		c.tailStdPipe(stdoutPath, request.Hooks.OnExecuteStdout, done)
	})
	safego.Go(func() {
		defer wg.Done()
		c.tailStdPipe(stderrPath, request.Hooks.OnExecuteStderr, done)
	})

	mp, err := startManagedProcessCmd(cmd)
	if err != nil {
		close(done)
		wg.Wait()
		request.Hooks.OnExecuteInit(session)
		request.Hooks.OnExecuteError(&execute.ErrorOutput{
			EName:     "CommandExecError",
			EValue:    err.Error(),
			Traceback: []string{err.Error()},
		})
		log.Error("CommandExecError: error starting commands: %v", err)
		return nil
	}

	kernel := &commandKernel{
		pid:          mp.Pid(),
		stdoutPath:   stdoutPath,
		stderrPath:   stderrPath,
		startedAt:    startAt,
		running:      true,
		content:      request.Code,
		isBackground: false,
	}
	c.storeCommandKernel(session, kernel)
	request.Hooks.OnExecuteInit(session)

	safego.Go(func() {
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				select {
				case <-done:
					return
				default:
				}
				_ = mp.Signal(syscall.SIGKILL)
				return
			case sig := <-signals:
				if sig == nil {
					continue
				}
				if sig != syscall.SIGCHLD && sig != syscall.SIGURG {
					_ = mp.Signal(sig.(syscall.Signal))
				}
			}
		}
	})

	err = mp.Wait()
	close(done)
	wg.Wait()
	if err != nil {
		var eName, eValue string
		var traceback []string

		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			eName = "CommandExecError"
			eValue = strconv.Itoa(mp.ExitCode())
		} else {
			eName = "CommandExecError"
			eValue = err.Error()
		}
		traceback = []string{err.Error()}

		request.Hooks.OnExecuteError(&execute.ErrorOutput{
			EName:     eName,
			EValue:    eValue,
			Traceback: traceback,
		})

		log.Error("CommandExecError: error running commands: %v", err)
		c.markCommandFinished(session, mp.ExitCode(), err.Error())
		return nil
	}

	c.markCommandFinished(session, 0, "")
	request.Hooks.OnExecuteComplete(time.Since(startAt))
	return nil
}

// runBackgroundCommand executes shell commands in detached mode.
func (c *Controller) runBackgroundCommand(ctx context.Context, cancel context.CancelFunc, request *ExecuteCodeRequest) error {
	session := c.newContextID()
	request.Hooks.OnExecuteInit(session)

	pipe, err := c.combinedOutputDescriptor(session)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to get combined output descriptor: %w", err)
	}
	stdoutPath := c.combinedOutputFileName(session)
	stderrPath := c.combinedOutputFileName(session)

	signals := make(chan os.Signal, len(forwardSignals)+1)
	defer close(signals)
	signal.Notify(signals, forwardSignals...)
	defer signal.Stop(signals)

	startAt := time.Now()
	log.Info("received command: %v", log.SanitizeCommand(request.Code))
	// --noprofile/--norc are no-ops for `bash -c`, so shellCommand is not used here.
	shell := getShell()

	cmd, err := maybeHardenedCommand(shell, "-c", request.Code)
	if err != nil {
		cancel()
		return err
	}
	extraEnv := mergeExtraEnvs(loadExtraEnvFromFile(), request.Envs)
	cwd, err := pathutil.ExpandPathWithEnv(request.Cwd, extraEnv)
	if err != nil {
		cancel()
		return fmt.Errorf("resolve cwd: %w", err)
	}
	cmd.Dir = cwd
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	if !isolation.HardeningEnabled() {
		cred, err := buildCredential(request.Uid, request.Gid)
		if err != nil {
			cancel()
			return fmt.Errorf("build credential: %w", err)
		}
		cmd.SysProcAttr.Credential = cred
	}

	cmd.Stdout = pipe
	cmd.Stderr = pipe
	if isolation.HardeningEnabled() {
		cmd.Env = mergeEnvs(cmd.Env, extraEnv)
	} else {
		cmd.Env = mergeEnvs(os.Environ(), extraEnv)
	}

	// use DevNull as stdin so interactive programs exit immediately.
	devNull, err := os.Open(os.DevNull)
	if err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}

	mp, err := startManagedProcessCmd(cmd)
	kernel := &commandKernel{
		pid:          -1,
		stdoutPath:   stdoutPath,
		stderrPath:   stderrPath,
		startedAt:    startAt,
		running:      true,
		content:      request.Code,
		isBackground: true,
	}
	if err != nil {
		cancel()
		log.Error("CommandExecError: error starting commands: %v", err)
		kernel.running = false
		c.storeCommandKernel(session, kernel)
		c.markCommandFinished(session, 255, err.Error())
		return fmt.Errorf("failed to start commands: %w", err)
	}

	// Register the kernel synchronously so that GetCommandStatus callers
	// can find the session immediately after Execute returns. Previously
	// this happened inside the goroutine, creating a race where the HTTP
	// handler could return before the kernel was stored.
	kernel.pid = mp.Pid()
	c.storeCommandKernel(session, kernel)

	safego.Go(func() {
		defer pipe.Close()

		err = mp.Wait()
		cancel()
		if err != nil {
			log.Error("CommandExecError: error running commands: %v", err)
			c.markCommandFinished(session, mp.ExitCode(), err.Error())
			return
		}
		c.markCommandFinished(session, 0, "")
	})

	// ensure we kill the whole process group if the context is cancelled (e.g., timeout).
	safego.Go(func() {
		<-ctx.Done()
		_ = mp.Signal(syscall.SIGKILL) // best-effort
	})

	request.Hooks.OnExecuteComplete(time.Since(startAt))
	return nil
}

// maybeHardenedCommand returns a command wrapped through the hardening launcher
// when [hardening] is enabled, or a plain command otherwise. Context
// cancellation is handled by the caller's signal goroutines; this function
// does NOT use exec.CommandContext to avoid double-kill on context done.
func maybeHardenedCommand(name string, args ...string) (*exec.Cmd, error) {
	hcmd, err := isolation.LaunchWithHardening(append([]string{name}, args...))
	if err != nil && !errors.Is(err, isolation.ErrHardeningDisabled) {
		return nil, fmt.Errorf("hardening launch: %w", err)
	}
	if hcmd != nil {
		return hcmd, nil
	}
	return exec.Command(name, args...), nil
}
