// Copyright 2026 The OpenSandbox Authors

//go:build !windows

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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
)

// newBindsViewSession builds a synthetic session the way
// CreateIsolatedSession leaves one behind: resolved overlays (with upper
// directories for persisted overlay mode) and symlink-resolved bind sources.
func newBindsViewSession(
	t *testing.T,
	overlays []IsolatedOverlayOptions,
	uppers map[int]string,
	binds []isolation.BindMount,
) *isolatedSession {
	t.Helper()
	s := newIsolatedSession("binds-view", &IsolatedSessionOptions{
		Overlays: overlays,
		Binds:    binds,
	}, newStubIsolator(), nil)
	for i, upper := range uppers {
		s.overlays[i].upperDir = upper
	}
	return s
}

func TestNewMergedView_BindRouting(t *testing.T) {
	// Resolve symlinks: MergedView rejects symlinked roots, and t.TempDir()
	// sits under a symlink on macOS.
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wsLower := filepath.Join(base, "ws")
	wsUpper := filepath.Join(base, "upper-ws")
	rwSrc := filepath.Join(base, "bind-src")
	roSrc := filepath.Join(base, "bind-ro-src")
	for _, dir := range []string{wsLower, wsUpper, rwSrc, roSrc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rwSrc, "seed.txt"), []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roSrc, "ro.txt"), []byte("ro-value"), 0o644); err != nil {
		t.Fatal(err)
	}

	persist := true
	s := newBindsViewSession(t,
		[]IsolatedOverlayOptions{{Path: wsLower, Mode: "overlay", Persist: &persist}},
		map[int]string{0: wsUpper},
		[]isolation.BindMount{
			{Source: rwSrc, Dest: "/data"},
			{Source: roSrc, Dest: "/configs", ReadOnly: true},
		},
	)
	view := newMergedView(s)

	t.Run("read_via_dest_serves_source", func(t *testing.T) {
		data, err := view.ReadFile("/data/seed.txt")
		if err != nil || string(data) != "seed" {
			t.Fatalf("ReadFile /data/seed.txt = %q, %v", data, err)
		}
	})

	t.Run("write_via_dest_lands_in_source", func(t *testing.T) {
		if err := view.WriteFile("/data/api.txt", []byte("api"), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(rwSrc, "api.txt"))
		if err != nil || string(got) != "api" {
			t.Fatalf("bind write did not reach the host source: %v, %q", err, got)
		}
	})

	t.Run("readdir_via_dest_lists_source", func(t *testing.T) {
		entries, err := view.ReadDir("/data")
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		for _, want := range []string{"seed.txt", "api.txt"} {
			found := false
			for _, n := range names {
				if n == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("ReadDir /data missing %q, got %v", want, names)
			}
		}
	})

	t.Run("readonly_bind_rejects_writes", func(t *testing.T) {
		data, err := view.ReadFile("/configs/ro.txt")
		if err != nil || string(data) != "ro-value" {
			t.Fatalf("ReadFile /configs/ro.txt = %q, %v", data, err)
		}
		err = view.WriteFile("/configs/new.txt", []byte("x"), 0o644)
		if err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("write to ro bind = %v, want read-only denial", err)
		}
	})

	t.Run("path_outside_all_mounts_rejected", func(t *testing.T) {
		if _, err := view.Stat("/etc/hostname"); !errors.Is(err, isolation.ErrPathOutsideOverlays) {
			t.Fatalf("Stat /etc/hostname = %v, want ErrPathOutsideOverlays", err)
		}
	})

	t.Run("relative_paths_still_resolve_against_workspace", func(t *testing.T) {
		if err := view.WriteFile("relative.txt", []byte("rel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(wsUpper, "relative.txt")); err != nil {
			t.Fatalf("relative write did not resolve against the workspace overlay: %v", err)
		}
	})

	t.Run("rename_within_bind_moves_source", func(t *testing.T) {
		if err := view.Rename("/data/seed.txt", "/data/renamed.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(rwSrc, "renamed.txt")); err != nil {
			t.Fatalf("renamed file missing in source: %v", err)
		}
	})

	t.Run("rename_across_mounts_rejected", func(t *testing.T) {
		err := view.Rename("/data/api.txt", filepath.Join(wsLower, "stolen.txt"))
		if err == nil || !strings.Contains(err.Error(), "rename across mounts") {
			t.Fatalf("rename bind→overlay = %v, want cross-mount rejection", err)
		}
	})
}

// TestNewMergedView_BindShadowsOverlayOnSameDest mirrors bwrap: binds are
// appended after overlay segments, so a bind sharing an overlay's dest
// shadows it inside the namespace — the files view must agree.
func TestNewMergedView_BindShadowsOverlayOnSameDest(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(base, "shared")
	upper := filepath.Join(base, "upper-shared")
	bindSrc := filepath.Join(base, "bind-src")
	for _, dir := range []string{shared, upper, bindSrc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s := newBindsViewSession(t,
		[]IsolatedOverlayOptions{{Path: shared, Mode: "rw"}},
		nil,
		[]isolation.BindMount{{Source: bindSrc, Dest: shared}},
	)
	view := newMergedView(s)

	if err := view.WriteFile(filepath.Join(shared, "who.txt"), []byte("bind"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(bindSrc, "who.txt")); err != nil {
		t.Fatalf("write went to the overlay instead of the shadowing bind: %v", err)
	}
	if _, err := os.Stat(filepath.Join(shared, "who.txt")); !os.IsNotExist(err) {
		t.Fatalf("write leaked into the overlay path: %v", err)
	}
}

// TestNewMergedView_BindDestDefaultsToSource covers the bwrap parity rule
// that an empty Dest binds source onto itself, and the files view follows.
func TestNewMergedView_BindDestDefaultsToSource(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rwSrc := filepath.Join(base, "rw-src")
	wsLower := filepath.Join(base, "ws")
	for _, dir := range []string{rwSrc, wsLower} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	s := newBindsViewSession(t,
		[]IsolatedOverlayOptions{{Path: wsLower, Mode: "rw"}},
		nil,
		[]isolation.BindMount{{Source: rwSrc}},
	)
	view := newMergedView(s)

	if err := view.WriteFile(filepath.Join(rwSrc, "same.txt"), []byte("same"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(rwSrc, "same.txt"))
	if err != nil || string(got) != "same" {
		t.Fatalf("source==dest bind write broken: %v, %q", err, got)
	}
}

// TestNewMergedView_BindViewPassthroughSemantics pins the no-overlay
// semantics of bind views: symlinks resolve like the namespace, ".wh."
// names stay real files, and search results are rebased onto the dest.
func TestNewMergedView_BindViewPassthroughSemantics(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	wsLower := filepath.Join(base, "ws")
	rwSrc := filepath.Join(base, "bind-src")
	for _, dir := range []string{wsLower, rwSrc} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(rwSrc, "plain.txt"), []byte("P"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rwSrc, ".wh.plain.txt"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(rwSrc, "plain.txt"), filepath.Join(rwSrc, "alias.txt")); err != nil {
		t.Fatal(err)
	}

	persist := true
	s := newBindsViewSession(t,
		[]IsolatedOverlayOptions{{Path: wsLower, Mode: "overlay", Persist: &persist}},
		nil,
		[]isolation.BindMount{{Source: rwSrc, Dest: "/data"}},
	)
	view := newMergedView(s)

	// Symlinked entries read through, like `cat` inside the namespace.
	got, err := view.ReadFile("/data/alias.txt")
	if err != nil || string(got) != "P" {
		t.Fatalf("ReadFile through bind symlink = %q, %v", got, err)
	}

	// ".wh."-prefixed names are real files in a bind, not whiteouts.
	if got, err = view.ReadFile("/data/.wh.plain.txt"); err != nil {
		t.Fatalf("whiteout-style file must stay readable in a bind: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected content in .wh. file: %q", got)
	}

	// Search results must come back in namespace space so follow-up Stats
	// (as the SearchFiles handler performs) route to the bind, not the
	// workspace relative base.
	results, err := view.Search("/data", "**.txt")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range results {
		if p == "/data/plain.txt" {
			found = true
		}
		if _, err := view.Stat(p); err != nil {
			t.Fatalf("search result %s does not stat: %v", p, err)
		}
	}
	if !found {
		t.Fatalf("search results missing rebased /data/plain.txt: %v", results)
	}
}

// TestNewMergedView_BindsWithoutOverlaysDoesNotPanic guards the defensive
// branch: the RelativeBase index must not go out of range when a session
// somehow carries binds but no overlays (Create rejects this today).
func TestNewMergedView_BindsWithoutOverlaysDoesNotPanic(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(base, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}

	s := newBindsViewSession(t, nil, nil,
		[]isolation.BindMount{{Source: src, Dest: "/data"}},
	)
	view := newMergedView(s)

	if err := view.WriteFile("/data/x.txt", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(src, "x.txt")); err != nil {
		t.Fatalf("bind write missing in source: %v", err)
	}
}

// TestValidateBindMountStack pins the mount-stack collisions the files view
// cannot represent: duplicates, ancestor binds, and trusted-base shadowing.
// Bind == overlay/extra_writable dest is allowed (the later bind shadows in
// both views).
func TestValidateBindMountStack(t *testing.T) {
	cases := []struct {
		name        string
		overlays    []IsolatedOverlayOptions
		extra       []string
		binds       []BindMountSpec
		wantFailure string
	}{
		{
			name:     "bind equal to overlay dest is allowed",
			overlays: []IsolatedOverlayOptions{{Path: "/data"}},
			binds:    []BindMountSpec{{source: "/a", dest: "/data"}},
		},
		{
			name:     "bind inside overlay dest is allowed",
			overlays: []IsolatedOverlayOptions{{Path: "/data"}},
			binds:    []BindMountSpec{{source: "/a", dest: "/data/proj"}},
		},
		{
			name:  "bind equal to extra_writable is allowed",
			extra: []string{"/mnt/scratch"},
			binds: []BindMountSpec{{source: "/a", dest: "/mnt/scratch"}},
		},
		{
			name:        "duplicate bind dests rejected",
			binds:       []BindMountSpec{{source: "/a", dest: "/mnt/x"}, {source: "/b", dest: "/mnt/x"}},
			wantFailure: "duplicate bind destination",
		},
		{
			name:        "bind ancestor of overlay rejected",
			overlays:    []IsolatedOverlayOptions{{Path: "/data/proj"}},
			binds:       []BindMountSpec{{source: "/a", dest: "/data"}},
			wantFailure: "shadows mount",
		},
		{
			name:        "bind ancestor of extra_writable rejected",
			extra:       []string{"/mnt/scratch/sub"},
			binds:       []BindMountSpec{{source: "/a", dest: "/mnt/scratch"}},
			wantFailure: "shadows mount",
		},
		{
			name:        "bind ancestor of another bind rejected",
			binds:       []BindMountSpec{{source: "/a", dest: "/data"}, {source: "/b", dest: "/data/proj"}},
			wantFailure: "nested bind destinations",
		},
		{
			name:        "bind under /run rejected",
			binds:       []BindMountSpec{{source: "/a", dest: "/run/secrets"}},
			wantFailure: "trusted base mount",
		},
		{
			name:        "bind at /dev rejected",
			binds:       []BindMountSpec{{source: "/a", dest: "/dev"}},
			wantFailure: "trusted base mount",
		},
		{
			name:     "unrelated bind and overlay allowed",
			overlays: []IsolatedOverlayOptions{{Path: "/workspace"}},
			binds:    []BindMountSpec{{source: "/a", dest: "/mnt/data"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binds := make([]isolation.BindMount, 0, len(tc.binds))
			for _, b := range tc.binds {
				binds = append(binds, isolation.BindMount{Source: b.source, Dest: b.dest})
			}
			err := validateBindMountStack(tc.overlays, tc.extra, binds)
			if tc.wantFailure == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantFailure) {
				t.Fatalf("error %v, want containing %q", err, tc.wantFailure)
			}
		})
	}
}

type BindMountSpec struct {
	source string
	dest   string
}
