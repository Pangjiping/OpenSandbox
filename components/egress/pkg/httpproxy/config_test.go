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

package httpproxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
)

func TestLoadConfigFromEnv_Disabled(t *testing.T) {
	t.Setenv(constants.EnvHTTPTransparent, "")
	t.Setenv(constants.EnvHTTPProxyListen, "")
	t.Setenv(constants.EnvHTTPHeadersFile, "")
	cfg := LoadConfigFromEnv()
	require.False(t, cfg.Enabled)
	require.Equal(t, constants.DefaultHTTPProxyListen, cfg.ListenAddr)
	require.Nil(t, cfg.Inject)
}

func TestLoadConfigFromEnv_EnabledAndInjectFromKVFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "headers.env")
	content := `
# tenant
X-Test=v

X-Other = a=b
`
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))

	t.Setenv(constants.EnvHTTPTransparent, "true")
	t.Setenv(constants.EnvHTTPProxyListen, "127.0.0.1:9999")
	t.Setenv(constants.EnvHTTPHeadersFile, p)

	cfg := LoadConfigFromEnv()
	require.True(t, cfg.Enabled)
	require.Equal(t, "127.0.0.1:9999", cfg.ListenAddr)
	require.Equal(t, map[string]string{"X-Test": "v", "X-Other": "a=b"}, cfg.Inject)
	port, err := cfg.ListenPort()
	require.NoError(t, err)
	require.Equal(t, 9999, port)
}

func TestLoadConfigFromEnv_JSONStyleFileNoHeaders(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "old.json")
	require.NoError(t, os.WriteFile(p, []byte(`{"X-Test":"v"}`), 0o600))

	t.Setenv(constants.EnvHTTPTransparent, "true")
	t.Setenv(constants.EnvHTTPHeadersFile, p)

	cfg := LoadConfigFromEnv()
	require.True(t, cfg.Enabled)
	require.Nil(t, cfg.Inject)
}

func TestLoadConfigFromEnv_MissingFileIgnored(t *testing.T) {
	t.Setenv(constants.EnvHTTPTransparent, "1")
	t.Setenv(constants.EnvHTTPHeadersFile, filepath.Join(t.TempDir(), "nope.env"))
	cfg := LoadConfigFromEnv()
	require.True(t, cfg.Enabled)
	require.Nil(t, cfg.Inject)
}

func TestParseHeadersFileContent_KVQuoted(t *testing.T) {
	m := parseHeadersFileContent([]byte(`H="quoted value"`))
	require.Equal(t, map[string]string{"H": "quoted value"}, m)
}

func TestParseHeadersFileContent_OnlyComments(t *testing.T) {
	m := parseHeadersFileContent([]byte("# only\n\n# x"))
	require.Nil(t, m)
}
