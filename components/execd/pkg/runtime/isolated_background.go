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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/log"
)

// isolatedBackgroundRunDir is the workspace-relative directory for background
// run log and exit-code files (dot-dir, created by the session shell).
const isolatedBackgroundRunDir = ".execd/background-runs"

// isolatedBackgroundPollInterval is how often the watcher checks for the
// exit-code file of a background run.
const isolatedBackgroundPollInterval = 500 * time.Millisecond

// maxBackgroundLogReadBytes caps how much of a run's log a single read
// (remaining bytes after the cursor) loads into memory; clients page through
// the rest with the returned cursor.
const maxBackgroundLogReadBytes = 16 << 20 // 16 MiB

// isolatedBackgroundProbeTimeout bounds the preflight probe that verifies the
// run log directory is writable by the session uid before a run is accepted.
const isolatedBackgroundProbeTimeout = 5 * time.Second

// IsolatedBackgroundRun tracks a detached run inside an isolated session.
// Output and exit code are redirected by the session shell to files under the
// workspace's background-runs directory, readable from the host side.
type IsolatedBackgroundRun struct {
	ID        string
	SessionID string
	logPath   string
	exitPath  string
	// fallback*: used when the run directory cannot be created inside the
	// namespace (e.g. a lower-layer .execd blocks overlay copy-up); the exit
	// code is then written to the workspace root instead, so the watcher
	// still sees completion.
	fallbackLogPath  string
	fallbackExitPath string

	mu         sync.Mutex
	startedAt  time.Time
	finishedAt *time.Time
	exitCode   *int
	errMsg     string
	running    bool
}

// IsolatedBackgroundRunSnapshot is a consistent read of a background run.
type IsolatedBackgroundRunSnapshot struct {
	RunID      string
	SessionID  string
	Running    bool
	ExitCode   *int
	Error      string
	StartedAt  time.Time
	FinishedAt *time.Time
}

func (r *IsolatedBackgroundRun) markFinished(exitCode *int, errMsg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	r.exitCode = exitCode
	r.errMsg = errMsg
	r.running = false
	r.finishedAt = &now
}

func (r *IsolatedBackgroundRun) snapshot() IsolatedBackgroundRunSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return IsolatedBackgroundRunSnapshot{
		RunID:      r.ID,
		SessionID:  r.SessionID,
		Running:    r.running,
		ExitCode:   r.exitCode,
		Error:      r.errMsg,
		StartedAt:  r.startedAt,
		FinishedAt: r.finishedAt,
	}
}

// RunInIsolatedSessionBackground starts code detached inside the session and
// returns immediately with a run ID. Runs are serialized per session (shared
// stdin), but this only holds the run mutex long enough to submit the script.
// The detached process dies with the bwrap process group, so Delete reaps it.
func (r *IsolatedRunner) RunInIsolatedSessionBackground(
	id string,
	code string,
	envs map[string]string,
) (string, time.Time, error) {
	s := r.lookup(id)
	if s == nil {
		return "", time.Time{}, ErrContextNotFound
	}

	s.runMu.Lock()
	defer s.runMu.Unlock()

	if s.dead() {
		return "", time.Time{}, ErrSessionNotActive
	}

	// Capture the session pipes once under the lock: Delete closes and nils
	// them under s.mu, so a bare s.stdin read after the preflight could
	// dereference a nil writer. A captured pipe may still be closed by a
	// concurrent Delete — writes then fail cleanly with an error.
	s.mu.RLock()
	stdin, stdout := s.stdin, s.stdout
	s.mu.RUnlock()
	if stdin == nil || stdout == nil {
		return "", time.Time{}, fmt.Errorf("session not started")
	}

	paths, err := s.backgroundRunPaths()
	if err != nil {
		return "", time.Time{}, err
	}

	runID := uuid.New().String()

	// Preflight: verify the session uid can write the run log directory (the
	// run dir, or the workspace root fallback) before accepting the run. A
	// session whose workspace is not writable by its own uid (e.g. an
	// execd-created workspace owned by root with a setpriv session running as
	// another uid) would otherwise accept the run and ghost it: no log or
	// exit-code file could ever be written. The probe runs through the
	// session shell and its marker is consumed synchronously, so nothing
	// leaks into the shared stdout.
	if err := r.preflightBackgroundLogDir(s, stdin, stdout, paths); err != nil {
		return "", time.Time{}, err
	}

	// The background job redirects its output to the log file and writes the
	// exit code to the code file. The script's mkdir creates the run dir as
	// the session's own uid (so it is writable even when the session runs as
	// a different uid than execd); if the dir cannot be created or is not
	// writable (e.g. a lower-layer .execd blocks overlay copy-up), $D falls
	// back to the workspace root so completion is always reported. The outer
	// >/dev/null discards residual diagnostics so nothing leaks into the
	// session stdout that the next foreground run's end-marker scan consumes.
	script := "{ " + backgroundRunDirScript(paths) + "; ("
	if len(envs) > 0 {
		for k, v := range envs {
			script += "\nexport " + shellescape(k) + "=" + shellescape(v)
		}
	}
	script += "\n"
	script += code
	if !strings.HasSuffix(script, "\n") {
		script += "\n"
	}
	// Detach from the session shell's stdin so a stdin-reading background
	// command cannot steal script lines meant for the next foreground run.
	script += ") </dev/null >\"$D/" + runID + ".log\" 2>&1; echo $? >\"$D/" +
		runID + ".code\"; } >/dev/null 2>&1 &\n"

	// Publish the run record before writing the script so a concurrent
	// DeleteIsolatedSession (which sweeps run records after removing the
	// session) can never run its sweep before our record exists, leaving it
	// orphaned in bgRuns. If the write then fails (e.g. the session was
	// deleted and the pipe is closed), the record is removed again.
	startedAt := time.Now()
	run := &IsolatedBackgroundRun{
		ID:               runID,
		SessionID:        id,
		logPath:          filepath.Join(paths.hostRunDir, runID+".log"),
		exitPath:         filepath.Join(paths.hostRunDir, runID+".code"),
		fallbackLogPath:  filepath.Join(paths.hostWorkspace, runID+".log"),
		fallbackExitPath: filepath.Join(paths.hostWorkspace, runID+".code"),
		startedAt:        startedAt,
		running:          true,
	}
	s.activeBackgroundRuns.Add(1)
	r.bgRuns.Store(runID, run)

	if _, err := io.WriteString(stdin, script); err != nil {
		s.activeBackgroundRuns.Add(-1)
		r.bgRuns.Delete(runID)
		return "", time.Time{}, fmt.Errorf("write stdin: %w", err)
	}

	// Anchor the idle clock so a finished run's session is not reaped before
	// its idle window elapses.
	s.mu.Lock()
	s.lastRunAt = time.Now()
	s.mu.Unlock()

	// Recheck that the session is still registered: a concurrent Delete may
	// have removed it (and swept this run record) while we held the run
	// mutex, in which case returning the handle would hand the caller a run
	// ID that immediately 404s. The run script was already submitted, so
	// this only affects the response, not the work.
	if _, ok := r.ctrl.isolatedSessionMap.Load(id); !ok {
		s.activeBackgroundRuns.Add(-1)
		return "", time.Time{}, ErrSessionNotActive
	}

	go r.watchBackgroundRun(s, run)
	log.Info("started background run %s in session %s", runID, id)
	return runID, startedAt, nil
}

// backgroundRunDirScript returns a shell fragment that resolves $D to the run
// log directory if the session uid can create and write it, or to the
// workspace root otherwise. It must stay consistent between the preflight
// probe and the run script so both use the same location.
func backgroundRunDirScript(paths backgroundRunPaths) string {
	return "D=" + shellescape(paths.nsRunDir) +
		"; mkdir -p \"$D\" 2>/dev/null && [ -w \"$D\" ] || D=" +
		shellescape(paths.nsWorkspace)
}

// preflightBackgroundLogDir verifies through the session shell that the run
// log directory is writable by the session uid. The caller holds the run
// mutex, so the probe's marker scan on the shared stdout cannot race another
// run. Returns an error when no writable log location exists.
func (r *IsolatedRunner) preflightBackgroundLogDir(
	s *isolatedSession,
	stdin io.Writer,
	stdout io.ReadCloser,
	paths backgroundRunPaths,
) error {
	marker := fmt.Sprintf("__ISOLATED_BG_PROBE__%s", uuid.New().String())
	probeScript := backgroundRunDirScript(paths) +
		"\nif [ -w \"$D\" ]; then echo " + marker + " 0; else echo " + marker + " 1; fi\n"

	if _, err := io.WriteString(stdin, probeScript); err != nil {
		return fmt.Errorf("write preflight probe: %w", err)
	}

	probeCtx, cancel := context.WithTimeout(context.Background(), isolatedBackgroundProbeTimeout)
	defer cancel()
	exitCode, err := scanUntilMarker(probeCtx, stdout, marker, nil)
	if err != nil {
		return fmt.Errorf("background run preflight: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("background runs unavailable: workspace is not writable by the session uid")
	}
	return nil
}

// watchBackgroundRun marks the run finished when the session shell writes the
// exit-code file, or when the session dies (the run dies with it).
func (r *IsolatedRunner) watchBackgroundRun(s *isolatedSession, run *IsolatedBackgroundRun) {
	ticker := time.NewTicker(isolatedBackgroundPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.doneCh:
			// The session died (e.g. the run killed the session shell): mark
			// the run failed but keep the record and its (possibly partial)
			// log files so clients can observe "session terminated" and read
			// the output via run_status/run_logs. Both are swept when the
			// session is deleted or GC'd.
			run.markFinished(nil, "session terminated")
			s.activeBackgroundRuns.Add(-1)
			return
		case <-ticker.C:
			code, ok := readIsolatedRunExitCode(run.exitPath)
			if !ok {
				code, ok = readIsolatedRunExitCode(run.fallbackExitPath)
			}
			if !ok {
				continue
			}
			run.markFinished(&code, "")
			// Bound disk usage per run: truncate oversized logs to the read
			// cap once the run is done. Clients can never hold a cursor past
			// the cap (each read returns at most maxBackgroundLogReadBytes),
			// so the incremental protocol stays coherent.
			capIsolatedRunLog(run.logPath)
			capIsolatedRunLog(run.fallbackLogPath)
			// Refresh lastRunAt before clearing the active-run counter so a
			// concurrent idle collector can never observe counter==0 with the
			// stale submission timestamp and reap the session before the
			// client's idle window starts.
			s.mu.Lock()
			s.lastRunAt = time.Now()
			s.mu.Unlock()
			s.activeBackgroundRuns.Add(-1)
			return
		}
	}
}

// GetIsolatedBackgroundRun returns a snapshot of a background run, or
// ErrContextNotFound when no such run exists (unknown run ID, or the session
// and its runs were deleted).
func (r *IsolatedRunner) GetIsolatedBackgroundRun(
	sessionID string,
	runID string,
) (*IsolatedBackgroundRunSnapshot, error) {
	v, ok := r.bgRuns.Load(runID)
	if !ok {
		return nil, ErrContextNotFound
	}
	run, ok := v.(*IsolatedBackgroundRun)
	if !ok || run.SessionID != sessionID {
		return nil, ErrContextNotFound
	}
	snap := run.snapshot()
	return &snap, nil
}

// SeekIsolatedBackgroundOutput returns the combined log of a background run
// from the given byte cursor (at most maxBackgroundLogReadBytes), plus the new
// cursor (end offset) for the next incremental read.
func (r *IsolatedRunner) SeekIsolatedBackgroundOutput(
	sessionID string,
	runID string,
	cursor int64,
) ([]byte, int64, error) {
	v, ok := r.bgRuns.Load(runID)
	if !ok {
		return nil, -1, ErrContextNotFound
	}
	run, ok := v.(*IsolatedBackgroundRun)
	if !ok || run.SessionID != sessionID {
		return nil, -1, ErrContextNotFound
	}
	if cursor < 0 {
		return nil, -1, fmt.Errorf("cursor cannot be negative")
	}

	file, err := os.Open(run.logPath)
	if err != nil {
		file, err = os.Open(run.fallbackLogPath)
	}
	if err != nil {
		if os.IsNotExist(err) {
			// The shell creates the log file at redirect time, asynchronously
			// after the run handle is returned; treat a missing log as empty.
			return nil, 0, nil
		}
		return nil, -1, fmt.Errorf("open background run log: %w", err)
	}
	defer file.Close()

	if _, err := file.Seek(cursor, io.SeekStart); err != nil {
		return nil, -1, fmt.Errorf("seek background run log: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBackgroundLogReadBytes))
	if err != nil {
		return nil, -1, fmt.Errorf("read background run log: %w", err)
	}
	newCursor, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, -1, fmt.Errorf("read background run log position: %w", err)
	}
	return data, newCursor, nil
}

// removeIsolatedRunFiles best-effort deletes the log/exit-code files of a run
// (primary and fallback locations). Overlay workspaces lose them with the
// upper directory anyway; rw workspaces would otherwise keep them in the
// user's persistent workspace.
func removeIsolatedRunFiles(run *IsolatedBackgroundRun) {
	for _, p := range []string{run.logPath, run.exitPath, run.fallbackLogPath, run.fallbackExitPath} {
		_ = os.Remove(p)
	}
}

// removeSessionBackgroundRuns drops every run record of a session and removes
// the run's log/exit-code files. Called from DeleteIsolatedSession once the
// session (and its upper layer, for overlay workspaces) is torn down.
func (r *IsolatedRunner) removeSessionBackgroundRuns(sessionID string) {
	var runDir string
	r.bgRuns.Range(func(key, value any) bool {
		run, ok := value.(*IsolatedBackgroundRun)
		if !ok || run.SessionID != sessionID {
			return true
		}
		removeIsolatedRunFiles(run)
		if runDir == "" {
			runDir = filepath.Dir(run.logPath)
		}
		r.bgRuns.Delete(key)
		return true
	})
	if runDir != "" {
		// Best-effort: drop the execd-managed run dir when empty (rw
		// workspaces only; overlay uppers are already gone). The .execd
		// parent is removed only when the run dir removal succeeded, so a
		// user-owned .execd file or non-empty dir is never touched.
		if err := os.Remove(runDir); err == nil {
			_ = os.Remove(filepath.Dir(runDir))
		}
	}
}

// backgroundRunPaths holds namespace and host paths for a background run.
type backgroundRunPaths struct {
	nsRunDir      string // <workspace>/.execd/background-runs
	nsWorkspace   string // workspace path as seen inside the namespace
	hostRunDir    string // host-side run dir (upper layer for overlay, workspace for rw)
	hostWorkspace string // host-side workspace root (upper dir for overlay)
}

// backgroundRunPaths returns the namespace and host paths of the background
// run directory. The host path is the upper layer for overlay workspaces and
// the workspace itself for rw workspaces; read-only workspaces reject
// background runs (no host-visible writable location for logs).
func (s *isolatedSession) backgroundRunPaths() (backgroundRunPaths, error) {
	paths := backgroundRunPaths{
		nsRunDir:      filepath.Join(s.opts.WorkspacePath, isolatedBackgroundRunDir),
		nsWorkspace:   s.opts.WorkspacePath,
		hostWorkspace: s.opts.WorkspacePath,
	}
	switch isolation.WorkspaceMode(s.opts.WorkspaceMode) {
	case isolation.WorkspaceRW:
		paths.hostRunDir = paths.nsRunDir
	case isolation.WorkspaceOverlay, "":
		if s.upperDir == "" {
			return backgroundRunPaths{}, fmt.Errorf("background runs unavailable: session has no upper directory")
		}
		paths.hostRunDir = filepath.Join(s.upperDir, isolatedBackgroundRunDir)
		paths.hostWorkspace = s.upperDir
	default: // WorkspaceRO
		return backgroundRunPaths{}, fmt.Errorf("background runs not supported in read-only workspace mode")
	}
	return paths, nil
}

// capIsolatedRunLog truncates a run's log file to maxBackgroundLogReadBytes
// when it grew past the cap, bounding per-run disk usage. Best-effort.
func capIsolatedRunLog(path string) {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= maxBackgroundLogReadBytes {
		return
	}
	_ = os.Truncate(path, maxBackgroundLogReadBytes)
}

// readIsolatedRunExitCode reads a background run's exit-code file; missing or
// not-yet-written files report not-ready.
func readIsolatedRunExitCode(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return 0, false
	}
	code, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return code, true
}
