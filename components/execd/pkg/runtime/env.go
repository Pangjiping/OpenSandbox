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
	"fmt"
	"os"
	"strings"

	"github.com/alibaba/opensandbox/execd/pkg/binding"
	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/log"
	"github.com/alibaba/opensandbox/execd/pkg/util/pathutil"
)

// loadExtraEnvFromFile reads key=value lines from EXECD_ENVS (if set).
// Empty lines and lines starting with '#' are ignored.
func loadExtraEnvFromFile() map[string]string {
	path := os.Getenv("EXECD_ENVS")
	if path == "" {
		return nil
	}
	resolvedPath, err := pathutil.ExpandPath(path)
	if err != nil {
		log.Warn("EXECD_ENVS: failed to resolve file path %s: %v", path, err)
		return nil
	}

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		log.Warn("EXECD_ENVS: failed to read file %s: %v", resolvedPath, err)
		return nil
	}

	envs := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			log.Warn("EXECD_ENVS: skip malformed line: %s", line)
			continue
		}
		envs[pathutil.EnvKey(kv[0])] = os.ExpandEnv(kv[1])
	}

	return envs
}

// mergeEnvs overlays extra into base and returns a merged slice.
func mergeEnvs(base []string, extra map[string]string) []string {
	if len(extra) == 0 {
		return base
	}

	merged := make(map[string]string, len(base)+len(extra))
	for _, kv := range base {
		pair := strings.SplitN(kv, "=", 2)
		if len(pair) == 2 {
			merged[pathutil.EnvKey(pair[0])] = pair[1]
		}
	}

	for k, v := range extra {
		merged[pathutil.EnvKey(k)] = v
	}

	out := make([]string, 0, len(merged))
	for k, v := range merged {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}

	return out
}

// bindingSandboxEnvs returns the sandbox-level envs provided by POST /internal/init,
// or nil when no RuntimeBinding (or no envs) is applied.
func bindingSandboxEnvs() map[string]string {
	b := binding.Current()
	if b == nil || len(b.Envs) == 0 {
		return nil
	}
	return b.Envs
}

// UserEnvOverlay builds the standard user-workload env overlay, layered with
// the /init RuntimeBinding as the authoritative source:
//
//	sandbox envs (/internal/init) < EXECD_ENVS file < extras (session/request)
//
// Binding-authoritative values (OPENSANDBOX_ID) are forced on top so user
// envs cannot spoof sandbox attribution.
func UserEnvOverlay(extras ...map[string]string) map[string]string {
	var merged map[string]string
	layers := make([]map[string]string, 0, len(extras)+2)
	if envs := bindingSandboxEnvs(); envs != nil {
		layers = append(layers, envs)
	}
	if fileEnvs := loadExtraEnvFromFile(); len(fileEnvs) > 0 {
		layers = append(layers, fileEnvs)
	}
	layers = append(layers, extras...)

	for _, layer := range layers {
		if len(layer) == 0 {
			continue
		}
		if merged == nil {
			merged = make(map[string]string, len(layer))
		}
		for k, v := range layer {
			merged[pathutil.EnvKey(k)] = v
		}
	}

	if merged == nil {
		merged = make(map[string]string)
	}
	if b := binding.Current(); b != nil && b.SandboxID != "" {
		merged["OPENSANDBOX_ID"] = b.SandboxID
	}
	return merged
}

// filterEnvBlacklist removes execd's own config/credential env entries from a
// base environ slice.
func filterEnvBlacklist(env []string) []string {
	return filterEnvNames(env, isolation.ExecdConfigEnvBlacklist())
}

// filterEnvNames removes the named env entries from a base environ slice
// (case-insensitive on names).
func filterEnvNames(env []string, names []string) []string {
	blocked := make(map[string]struct{}, len(names))
	for _, name := range names {
		blocked[strings.ToUpper(name)] = struct{}{}
	}

	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, found := blocked[strings.ToUpper(name)]; found {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

// UserProcessEnvironment returns the environment for user processes started
// outside a request (PTY/pipe sessions, lifecycle hooks): the daemon
// environment minus execd config/credential vars, overlaid with the standard
// user env (sandbox binding envs < EXECD_ENVS file).
func UserProcessEnvironment() []string {
	return mergeEnvs(filterEnvBlacklist(os.Environ()), UserEnvOverlay())
}
