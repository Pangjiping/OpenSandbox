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

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibaba/opensandbox/ingress/pkg/proxy/connectivity"
)

func TestIngressMuxReservesOnlyExactHealthPaths(t *testing.T) {
	dataPlane := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proxied:" + r.URL.Path))
	})
	networkReadiness := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("network-readiness"))
	})
	mux := newIngressMux(dataPlane, networkReadiness)

	tests := []struct {
		path string
		want string
	}{
		{path: "/readyz", want: "proxied:/readyz"},
		{path: "/livez", want: "proxied:/livez"},
		{path: "/status.ok/network-readiness", want: "network-readiness"},
		{path: "/status.ok/network-readiness/", want: "proxied:/status.ok/network-readiness/"},
		{path: "/status.ok", want: "OK"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			if recorder.Code != http.StatusOK || recorder.Body.String() != test.want {
				t.Fatalf("response = %d %q, want 200 %q", recorder.Code, recorder.Body.String(), test.want)
			}
		})
	}
}

func TestInvalidNetworkReadinessConfigDisablesObserver(t *testing.T) {
	observer, handler, err := newNetworkReadiness(connectivity.TrackerConfig{})
	if err == nil || observer != nil {
		t.Fatalf("newNetworkReadiness() = (%v, _, %v), want nil observer and error", observer, err)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/status.ok/network-readiness", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("disabled handler status = %d, want 404", recorder.Code)
	}
}
