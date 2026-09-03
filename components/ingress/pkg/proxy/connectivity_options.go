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

package proxy

import (
	"net"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/alibaba/opensandbox/ingress/pkg/proxy/connectivity"
)

// Option configures optional proxy behavior without changing existing callers.
type Option func(*proxyOptions)

type proxyOptions struct {
	connectObserver connectivity.Observer
}

// WithConnectObserver observes HTTP and WebSocket TCP connection attempts.
func WithConnectObserver(observer connectivity.Observer) Option {
	return func(options *proxyOptions) {
		options.connectObserver = observer
	}
}

func newObservedHTTPTransport(observer connectivity.Observer) http.RoundTripper {
	if observer == nil {
		return nil
	}

	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil
	}
	transport := baseTransport.Clone()
	baseDialContext := transport.DialContext
	if baseDialContext == nil {
		baseDialer := &net.Dialer{}
		baseDialContext = baseDialer.DialContext
	}
	transport.DialContext = connectivity.WrapDialContext(baseDialContext, observer, "http")
	return transport
}

func newObservedWebSocketDialer(observer connectivity.Observer) *websocket.Dialer {
	if observer == nil {
		return nil
	}

	dialer := *websocket.DefaultDialer
	baseDialer := &net.Dialer{}
	dialer.NetDialContext = connectivity.WrapDialContext(baseDialer.DialContext, observer, "websocket")
	return &dialer
}
