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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/execd/pkg/binding"
	"github.com/alibaba/opensandbox/execd/pkg/isolation"
)

func TestLoadExtraEnvFromFileUnset(t *testing.T) {
	t.Setenv("EXECD_ENVS", "")
	require.Nil(t, loadExtraEnvFromFile(), "expected nil when EXECD_ENVS unset")
}

func TestLoadExtraEnvFromFileParsesAndExpands(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "env")

	t.Setenv("EXECD_ENVS", envFile)
	t.Setenv("BASE_DIR", "/opt/base")

	content := strings.Join([]string{
		"# comment",
		"FOO=bar",
		"PATH=$BASE_DIR/bin",
		"MALFORMED",
		"EMPTY=",
		"",
	}, "\n")

	require.NoError(t, os.WriteFile(envFile, []byte(content), 0o644))

	got := loadExtraEnvFromFile()
	require.Len(t, got, 3)
	require.Equal(t, "bar", got["FOO"])
	require.Equal(t, "/opt/base/bin", got["PATH"])
	val, ok := got["EMPTY"]
	require.True(t, ok)
	require.Equal(t, "", val)
}

func TestLoadExtraEnvFromFileMissingFile(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "does-not-exist")
	t.Setenv("EXECD_ENVS", envFile)

	require.Nil(t, loadExtraEnvFromFile(), "expected nil for missing file")
}

func TestLoadExtraEnvFromFileSupportsHomePath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	envFile := filepath.Join(home, "extra.env")
	require.NoError(t, os.WriteFile(envFile, []byte("FOO=bar\n"), 0o644))
	t.Setenv("EXECD_ENVS", "~/extra.env")

	got := loadExtraEnvFromFile()
	require.Equal(t, "bar", got["FOO"])
}

func TestMergeEnvsOverlaysExtra(t *testing.T) {
	base := []string{"A=1", "B=2"}
	extra := map[string]string{"B": "override", "C": "3"}

	merged := mergeEnvs(base, extra)
	got := make(map[string]string)
	for _, kv := range merged {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			got[parts[0]] = parts[1]
		}
	}

	require.Len(t, got, 3)
	require.Equal(t, "1", got["A"])
	require.Equal(t, "override", got["B"])
	require.Equal(t, "3", got["C"])
}

// applyTestBinding installs a RuntimeBinding for the duration of the test and
// restores the previous state afterwards.
func applyTestBinding(t *testing.T, b *binding.RuntimeBinding) {
	t.Helper()
	previous := binding.Apply(b)
	t.Cleanup(func() { binding.Apply(previous) })
}

func TestUserEnvOverlayEmptyWithoutBinding(t *testing.T) {
	t.Setenv("EXECD_ENVS", "")
	applyTestBinding(t, nil)

	got := UserEnvOverlay(map[string]string{"REQ": "1"})
	require.Equal(t, map[string]string{"REQ": "1"}, got)
}

func TestUserEnvOverlayLayersBindingFileRequest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "env"), []byte("FILE_ONLY=f1\nSHARED=file\n"), 0o644))
	t.Setenv("EXECD_ENVS", filepath.Join(dir, "env"))

	applyTestBinding(t, &binding.RuntimeBinding{
		SandboxID: "sandbox-1",
		Envs:      map[string]string{"SANDBOX_ONLY": "s1", "SHARED": "sandbox"},
	})

	// Sandbox env < file env; request env beats both.
	got := UserEnvOverlay(map[string]string{"SHARED": "request"})
	require.Equal(t, "s1", got["SANDBOX_ONLY"])
	require.Equal(t, "f1", got["FILE_ONLY"])
	require.Equal(t, "request", got["SHARED"])

	// The runtime (.env file) layer overrides the sandbox layer.
	require.Equal(t, "file", UserEnvOverlay()["SHARED"])
}

func TestUserEnvOverlayForcesSandboxID(t *testing.T) {
	t.Setenv("EXECD_ENVS", "")
	applyTestBinding(t, &binding.RuntimeBinding{SandboxID: "authoritative"})

	got := UserEnvOverlay(map[string]string{"OPENSANDBOX_ID": "spoofed"})
	require.Equal(t, "authoritative", got["OPENSANDBOX_ID"])
}

func TestUserEnvOverlayNoBindingKeepsFileLayer(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "env"), []byte("FOO=bar\n"), 0o644))
	t.Setenv("EXECD_ENVS", filepath.Join(dir, "env"))
	applyTestBinding(t, nil)

	got := UserEnvOverlay()
	require.Equal(t, "bar", got["FOO"])
	require.NotContains(t, got, "OPENSANDBOX_ID")
}

func TestFilterEnvNamesRemovesConfigVars(t *testing.T) {
	env := []string{"PATH=/usr/bin", "EXECD_ACCESS_TOKEN=secret", "JUPYTER_TOKEN=tok", "KEEP=1"}

	filtered := filterEnvNames(env, isolation.ExecdConfigEnvBlacklist())

	require.Contains(t, filtered, "PATH=/usr/bin")
	require.Contains(t, filtered, "KEEP=1")
	require.Len(t, filtered, 2)
}

func TestUserProcessEnvironmentFiltersBlacklist(t *testing.T) {
	t.Setenv("EXECD_ACCESS_TOKEN", "secret")
	t.Setenv("EXECD_ENVS", "")
	applyTestBinding(t, &binding.RuntimeBinding{
		SandboxID: "sandbox-1",
		Envs:      map[string]string{"SANDBOX_ONLY": "s1"},
	})

	env := UserProcessEnvironment()
	joined := strings.Join(env, "\n")
	require.Contains(t, joined, "SANDBOX_ONLY=s1")
	require.Contains(t, joined, "OPENSANDBOX_ID=sandbox-1")
	require.NotContains(t, joined, "EXECD_ACCESS_TOKEN")
}
