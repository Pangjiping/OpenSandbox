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

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// LoadPolicyFromEnvVar parses policy from envName; empty → default deny.
func LoadPolicyFromEnvVar(envName string) (*NetworkPolicy, error) {
	raw := os.Getenv(envName)
	if raw == "" {
		return DefaultDenyPolicy(), nil
	}
	return ParsePolicy(raw)
}

// LoadInitialPolicy prefers policyFile when present and valid; else envName (see LoadPolicyFromEnvVar).
func LoadInitialPolicy(policyFile, envName string) (*NetworkPolicy, error) {
	policyFile = strings.TrimSpace(policyFile)
	if policyFile == "" {
		return LoadPolicyFromEnvVar(envName)
	}

	data, err := os.ReadFile(policyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return LoadPolicyFromEnvVar(envName)
		}
		return nil, err
	}

	raw := strings.TrimSpace(string(data))
	if raw == "" {
		log.Warnf("egress policy file %s is empty; falling back to %s", policyFile, envName)
		return LoadPolicyFromEnvVar(envName)
	}

	pol, err := ParsePolicy(raw)
	if err != nil {
		log.Warnf("egress policy file %s is invalid: %v; falling back to %s", policyFile, err, envName)
		return LoadPolicyFromEnvVar(envName)
	}

	log.Infof("loaded egress policy from %s", policyFile)
	return pol, nil
}

// SavePolicyFile writes JSON atomically; empty path is a no-op.
func SavePolicyFile(path string, p *NetworkPolicy) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if p == nil {
		p = DefaultDenyPolicy()
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".egress-policy-*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
