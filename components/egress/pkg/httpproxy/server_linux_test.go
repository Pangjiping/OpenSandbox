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

//go:build linux

package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestForwardHTTP_UpstreamReceivesInjectedHeaders verifies that headers from the inject map are
// present on the request seen by the upstream HTTP server (simulating the “peer” service).
// This does not use iptables or SO_ORIGINAL_DST; it calls forwardHTTP with an explicit
// netip.AddrPort. End-to-end transparent redirect is covered by deployment tests / manual runs.
func TestForwardHTTP_UpstreamReceivesInjectedHeaders(t *testing.T) {
	const wantHeader = "X-Egress-Injected"
	const wantValue = "expected-header-value"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.Header.Get(wantHeader))
	}))
	defer upstream.Close()

	tcpAddr := upstream.Listener.Addr().(*net.TCPAddr)
	orig, err := netip.ParseAddrPort(net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)))
	require.NoError(t, err)

	srv := &server{
		inject: map[string]string{wantHeader: wantValue},
		dialer: &net.Dialer{Timeout: 5 * time.Second},
	}

	cProxy, cApp := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.forwardHTTP(cProxy, orig)
	}()

	// Client side of the proxied connection: plain HTTP as an app would send.
	_, err = fmt.Fprintf(cApp, "GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(cApp), nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, wantValue, string(body))

	require.NoError(t, cApp.Close())
	<-done
}
