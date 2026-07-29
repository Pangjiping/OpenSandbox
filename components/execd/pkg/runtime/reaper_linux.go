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
	"golang.org/x/sys/unix"
)

// reapLoop uses wait4(-1) to reap all exited children. In init mode this is
// the only correct behaviour — PID 1 must reap all reparented orphans.
// Non-managed children (bash sessions, PTY, isolated sessions) that still
// rely on Cmd.Wait() will lose their exit statuses during init mode. These
// paths must be migrated to managedProcess before enabling init mode.
func (r *reaper) reapLoop() {
	for range r.sigchld {
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if pid <= 0 || err != nil {
				break
			}
			r.dispatch(pid, ws)
		}
	}
}

func (r *reaper) dispatch(pid int, ws unix.WaitStatus) {
	r.mu.Lock()
	ch, ok := r.owners[pid]
	if ok {
		delete(r.owners, pid)
		r.mu.Unlock()
		ch <- ws
		return
	}
	// start/register race: child exited before register() was called.
	// Buffer in pending so register() delivers it immediately.
	r.pending[pid] = ws
	r.mu.Unlock()
}
