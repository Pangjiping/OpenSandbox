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

package telemetry

import (
	"net"
	"net/url"
	"strings"
)

// OTLPEndpointHostPort returns the host and port of the configured OTLP
// endpoint. Endpoint precedence matches the exporters:
// OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, then OTEL_EXPORTER_OTLP_ENDPOINT.
// A missing port falls back to the scheme default (https->443, http->80);
// a bare host:port or host without a scheme is treated as https. Domain
// hosts are returned without the trailing dot, matching DNS policy
// normalization. ok is false when no endpoint is configured or it cannot
// be parsed.
func OTLPEndpointHostPort() (host, port string, ok bool) {
	raw := otlpEndpointFromEnv()
	if raw == "" {
		return "", "", false
	}
	return parseOTLPEndpoint(raw)
}

// OTLPEndpointFallbackHostPort returns the exporter fallback destination used
// when no standard OTEL endpoint env var is set: the resolved node IP
// (HOST_IP, then /etc/hostinfo) on the default OTLP/HTTP port 4318. ok is
// false when no node IP can be resolved.
func OTLPEndpointFallbackHostPort() (host, port string, ok bool) {
	ip, ok := resolveNodeIP()
	if !ok {
		return "", "", false
	}
	return ip, otlpHTTPPort, true
}

func parseOTLPEndpoint(raw string) (host, port string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", false
		}
		host = strings.TrimRight(strings.TrimSpace(u.Hostname()), ".")
		if host == "" {
			return "", "", false
		}
		port = u.Port()
		if port == "" {
			port = defaultPortForScheme(u.Scheme)
		}
		return host, port, true
	}
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = strings.TrimSpace(h), strings.TrimSpace(p)
		host = strings.TrimRight(host, ".")
		if host == "" {
			return "", "", false
		}
		return host, port, true
	}
	host = strings.TrimRight(strings.TrimSpace(raw), ".")
	if host == "" {
		return "", "", false
	}
	// No scheme: per OTLP spec the https scheme (port 443) is assumed.
	return host, "443", true
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}
