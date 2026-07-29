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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// reaper is the single central reaper that owns all wait4 calls for execd-owned
// children. It runs exactly one reapLoop per process. All child lifecycle
// (managedProcess, entrypoint, etc.) registers with this reaper instead of
// calling Cmd.Wait() directly.
type reaper struct {
	mu      sync.Mutex
	started bool
	owners  map[int]chan<- unix.WaitStatus
	pending map[int]unix.WaitStatus
	sigchld chan os.Signal
}

var globalReaper = &reaper{
	owners:  make(map[int]chan<- unix.WaitStatus),
	pending: make(map[int]unix.WaitStatus),
}

// register records pid as owned. If a pending status already exists (child
// exited before registration), it is delivered immediately.
func (r *reaper) register(pid int, ch chan<- unix.WaitStatus) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ws, ok := r.pending[pid]; ok {
		delete(r.pending, pid)
		r.mu.Unlock()
		ch <- ws
		return
	}
	r.owners[pid] = ch
	r.mu.Unlock()
}

// deregister removes pid from the owner registry and clears any buffered
// pending status.
func (r *reaper) deregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.owners, pid)
	delete(r.pending, pid)
}

// StartReaper initialises the central reaper. Idempotent; subsequent calls are
// no-ops. Installs the SIGCHLD handler synchronously so no exit is missed.
//
// Callers outside init mode should NOT start the reaper — it uses wait4(-1)
// which would steal exit statuses from non-managed children (bash sessions,
// PTY, isolated sessions) that still rely on Cmd.Wait(). Use
// startManagedProcessCmd which falls back to Cmd.Wait() when the reaper is
// not running.
func StartReaper() {
	globalReaper.start()
}

// start initialises the reaper loop in a background goroutine. It installs the
// SIGCHLD handler synchronously before returning, so no child exit status is
// lost between registration and reapLoop entering its select loop.
//
// Idempotent; must be called before any child is launched.
func (r *reaper) start() {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()

	r.sigchld = make(chan os.Signal, 1)
	signal.Notify(r.sigchld, syscall.SIGCHLD)
	go r.reapLoop()
}

// isStarted reports whether the reaper loop has been started.
func (r *reaper) isStarted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started
}
