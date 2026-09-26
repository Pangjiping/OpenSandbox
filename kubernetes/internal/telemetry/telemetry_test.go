// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
)

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    map[string]string
		wantErr bool
	}{
		{name: "empty", raw: "", want: map[string]string{}},
		{name: "single", raw: "authorization=Bearer abc", want: map[string]string{"authorization": "Bearer abc"}},
		{name: "multiple", raw: "k1=v1, k2=v2", want: map[string]string{"k1": "v1", "k2": "v2"}},
		{name: "value with equals", raw: "k=v=1", want: map[string]string{"k": "v=1"}},
		{name: "missing value", raw: "k1=v1,,k2", wantErr: true},
		{name: "missing key", raw: "=v1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeaders(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseHeaders() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("ParseHeaders()[%s] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestEndpointFromEnv(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(MetricsEndpointEnv, "")
		t.Setenv(EndpointEnv, "")
		if got := EndpointFromEnv(); got != "" {
			t.Fatalf("EndpointFromEnv() = %q, want empty", got)
		}
	})
	t.Run("generic only", func(t *testing.T) {
		t.Setenv(MetricsEndpointEnv, "")
		t.Setenv(EndpointEnv, "http://collector:4318")
		if got := EndpointFromEnv(); got != "http://collector:4318" {
			t.Fatalf("EndpointFromEnv() = %q", got)
		}
	})
	t.Run("metrics-specific wins", func(t *testing.T) {
		t.Setenv(MetricsEndpointEnv, "http://collector:4318")
		t.Setenv(EndpointEnv, "http://other:4318")
		if got := EndpointFromEnv(); got != "http://collector:4318" {
			t.Fatalf("EndpointFromEnv() = %q", got)
		}
	})
}

func TestSanitizeEndpoint(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain", in: "http://collector:4318", want: "http://collector:4318"},
		{name: "drops query and user", in: "http://user:pass@collector:4318/v1/metrics?token=secret", want: "http://collector:4318/v1/metrics"},
		{name: "invalid", in: "::::", want: "<invalid>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeEndpoint(tt.in); got != tt.want {
				t.Fatalf("SanitizeEndpoint(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetupDisabledWithoutEndpoint(t *testing.T) {
	shutdown, err := Setup(context.Background(), Config{Endpoint: ""})
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	if shutdown == nil {
		t.Fatal("Setup() returned nil shutdown for disabled telemetry")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}
}

func TestSetupRejectsInvalidEndpoint(t *testing.T) {
	for _, endpoint := range []string{"collector:4318", "ftp://collector:4318", "http://"} {
		if _, err := Setup(context.Background(), Config{Endpoint: endpoint}); err == nil {
			t.Errorf("Setup(endpoint=%q) expected error", endpoint)
		}
	}
}

// TestSetupExportsMetrics verifies the full wiring: the global meter provider
// installed by Setup exports recorded metrics over OTLP/HTTP and flushes them
// on shutdown.
func TestSetupExportsMetrics(t *testing.T) {
	captureMeterProvider(t)

	requests := make(chan *http.Request, 4)
	bodies := make(chan []byte, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- r
		bodies <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	shutdown, err := Setup(context.Background(), Config{Endpoint: server.URL})
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	counter, err := otel.GetMeterProvider().Meter("telemetry_test").Int64Counter("telemetry.test.counter")
	if err != nil {
		t.Fatalf("failed to create counter: %v", err)
	}
	counter.Add(context.Background(), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}

	select {
	case r := <-requests:
		if got := r.URL.Path; got != "/v1/metrics" {
			t.Errorf("export path = %q, want /v1/metrics", got)
		}
		if ct := r.Header.Get("Content-Type"); ct == "" {
			t.Error("export request missing Content-Type")
		}
		if body := <-bodies; len(body) == 0 {
			t.Error("export request has empty body")
		}
	default:
		t.Fatal("no OTLP export request reached the test server")
	}
}

// TestSetupKeepsCustomExportPath verifies a URL with an explicit path is used as-is.
func TestSetupKeepsCustomExportPath(t *testing.T) {
	captureMeterProvider(t)

	var gotPath string
	pathCh := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		gotPath = r.URL.Path
		pathCh <- gotPath
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	shutdown, err := Setup(context.Background(), Config{Endpoint: server.URL + "/custom/v1/metrics"})
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	counter, err := otel.GetMeterProvider().Meter("telemetry_test").Int64Counter("telemetry.test.counter")
	if err != nil {
		t.Fatalf("failed to create counter: %v", err)
	}
	counter.Add(context.Background(), 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown() error = %v", err)
	}

	select {
	case p := <-pathCh:
		if p != "/custom/v1/metrics" {
			t.Fatalf("export path = %q, want /custom/v1/metrics", p)
		}
	default:
		t.Fatal("no OTLP export request reached the test server")
	}
	_ = gotPath
}

// captureMeterProvider registers cleanup that restores the current global
// meter provider, isolating tests from Setup's global mutation.
func captureMeterProvider(t *testing.T) {
	t.Helper()
	previous := otel.GetMeterProvider()
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
}
