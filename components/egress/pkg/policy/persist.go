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
	"io/fs"
	"os"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// loadPolicyFromEnvVar parses policy from envName; empty → default deny.
func loadPolicyFromEnvVar(envName string) (*NetworkPolicy, error) {
	raw := os.Getenv(envName)
	if raw == "" {
		return DefaultDenyPolicy(), nil
	}
	return ParsePolicy(raw)
}

// LoadInitialPolicy prefers policyFile when present and valid; else envName (see loadPolicyFromEnvVar).
func LoadInitialPolicy(policyFile, envName string) (*NetworkPolicy, error) {
	policyFile = strings.TrimSpace(policyFile)
	if policyFile == "" {
		return loadPolicyFromEnvVar(envName)
	}

	data, err := os.ReadFile(policyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return loadPolicyFromEnvVar(envName)
		}
		return nil, err
	}

	raw := strings.TrimSpace(string(data))
	if raw == "" {
		log.Warnf("egress policy file %s is empty; falling back to %s", policyFile, envName)
		return loadPolicyFromEnvVar(envName)
	}

	pol, err := ParsePolicy(raw)
	if err != nil {
		log.Warnf("egress policy file %s is invalid: %v; falling back to %s", policyFile, err, envName)
		return loadPolicyFromEnvVar(envName)
	}

	log.Infof("loaded egress policy from %s", policyFile)
	return pol, nil
}

// SavePolicyFile overwrites path with the full serialized policy (truncate + write + fsync).
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

	mode := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode() & fs.ModePerm
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
