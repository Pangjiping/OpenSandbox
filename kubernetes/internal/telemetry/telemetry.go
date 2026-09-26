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

// Package telemetry provides OpenTelemetry setup for the sandbox controller.
package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	// ServiceName identifies the controller in telemetry backends.
	ServiceName = "opensandbox-controller"

	// MetricsEndpointEnv is the metrics-specific OTLP endpoint environment variable.
	MetricsEndpointEnv = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	// EndpointEnv is the generic OTLP endpoint environment variable.
	EndpointEnv = "OTEL_EXPORTER_OTLP_ENDPOINT"

	// DefaultExportInterval matches the OTel periodic reader default.
	DefaultExportInterval = 60 * time.Second
)

// Config holds the OTLP export configuration for the controller.
type Config struct {
	// Endpoint is an absolute OTLP/HTTP URL, e.g. "http://collector:4318".
	// The default "/v1/metrics" path is appended when the URL has no path.
	// Empty disables export.
	Endpoint string
	// Headers are attached to every OTLP export request. When empty, the
	// exporter falls back to OTEL_EXPORTER_OTLP_HEADERS / OTEL_EXPORTER_OTLP_METRICS_HEADERS.
	Headers map[string]string
	// Interval is the metric export interval. Defaults to DefaultExportInterval.
	Interval time.Duration
}

// EndpointFromEnv returns the OTLP endpoint configured through environment
// variables, preferring the metrics-specific variable. Returns "" if unset.
func EndpointFromEnv() string {
	if endpoint := strings.TrimSpace(os.Getenv(MetricsEndpointEnv)); endpoint != "" {
		return endpoint
	}
	return strings.TrimSpace(os.Getenv(EndpointEnv))
}

// ParseHeaders parses a comma-separated "key=value" header string.
func ParseHeaders(raw string) (map[string]string, error) {
	headers := make(map[string]string)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return headers, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) != 2 || kv[0] == "" || kv[1] == "" {
			return nil, fmt.Errorf("invalid OTLP header %q, expected format: key=value", pair)
		}
		headers[kv[0]] = kv[1]
	}
	return headers, nil
}

// SanitizeEndpoint returns the endpoint with any userinfo, query string, or
// fragment removed so it is safe to log.
func SanitizeEndpoint(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid>"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return parsed.String()
}

// Setup installs the global OpenTelemetry meter provider backed by an
// OTLP/HTTP metric exporter. It returns a shutdown function that flushes
// pending data; the caller must invoke it for graceful shutdown.
//
// When Config.Endpoint is empty, export is disabled and the returned shutdown
// is a no-op; instruments then record into the default no-op provider.
func Setup(ctx context.Context, cfg Config) (func(context.Context) error, error) {
	if cfg.Endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultExportInterval
	}

	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(semconv.ServiceName(ServiceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build telemetry resource: %w", err)
	}

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(cfg.Interval))),
	)
	otel.SetMeterProvider(provider)
	return provider.Shutdown, nil
}

// newExporter builds an OTLP/HTTP exporter from the config. Endpoint-less
// options are omitted so the exporter keeps reading standard OTEL_* environment
// variables for those settings.
func newExporter(ctx context.Context, cfg Config) (*otlpmetrichttp.Exporter, error) {
	opts := []otlpmetrichttp.Option{}
	if cfg.Endpoint != "" {
		options, err := endpointOptions(cfg.Endpoint)
		if err != nil {
			return nil, err
		}
		opts = append(opts, options...)
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}
	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
	}
	return exporter, nil
}

// endpointOptions maps an absolute OTLP/HTTP URL onto exporter options. A URL
// without a path keeps the exporter default "/v1/metrics" path.
func endpointOptions(endpoint string) ([]otlpmetrichttp.Option, error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid OTLP endpoint %q, expected an absolute http(s) URL", endpoint)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid OTLP endpoint scheme %q, expected http or https", parsed.Scheme)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		options := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(parsed.Host)}
		if parsed.Scheme != "https" {
			options = append(options, otlpmetrichttp.WithInsecure())
		}
		return options, nil
	}
	return []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(parsed.String())}, nil
}
