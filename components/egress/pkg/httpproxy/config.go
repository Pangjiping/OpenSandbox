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
	"bytes"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// Config controls the optional cleartext HTTP transparent proxy.
type Config struct {
	Enabled    bool
	ListenAddr string
	Inject     map[string]string
}

// ListenPort returns the TCP port from ListenAddr (host:port).
func (c Config) ListenPort() (int, error) {
	_, portStr, err := net.SplitHostPort(c.ListenAddr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(portStr)
}

// LoadConfigFromEnv parses OPENSANDBOX_EGRESS_HTTP_* variables and loads optional inject headers from file once.
func LoadConfigFromEnv() Config {
	cfg := Config{
		ListenAddr: envOrDefault(constants.EnvHTTPProxyListen, constants.DefaultHTTPProxyListen),
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(constants.EnvHTTPTransparent))) {
	case "1", "true", "yes", "y", "on":
		cfg.Enabled = true
	}
	cfg.Inject = loadHeadersFromFile(os.Getenv(constants.EnvHTTPHeadersFile))
	return cfg
}

func loadHeadersFromFile(path string) map[string]string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warnf("[http] inject headers file %q: read: %v", path, err)
		return nil
	}
	m := parseHeadersFileContent(data)
	if len(m) == 0 {
		return nil
	}
	return m
}

// parseHeadersFileContent parses line-oriented KEY=VALUE: one pair per line, optional # comments, empty lines ignored.
// The first '=' on each line separates header name from value; later '=' characters belong to the value.
// If the value is wrapped in a single pair of double quotes, they are stripped.
func parseHeadersFileContent(data []byte) map[string]string {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil
	}
	return parseKVHeaders(data)
}

func parseKVHeaders(data []byte) map[string]string {
	m := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for n, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			log.Warnf("[http] inject headers file: line %d: expected KEY=VALUE, skipping %q", n+1, line)
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		if k == "" {
			log.Warnf("[http] inject headers file: line %d: empty key, skipping", n+1)
			continue
		}
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		m[k] = v
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func envOrDefault(key, defaultVal string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return defaultVal
}
