// Copyright 2025 Alibaba Group Holding Ltd.
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
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	slogger "github.com/alibaba/opensandbox/internal/logger"
	"github.com/coder/websocket"
)

// WebSocketProxy is an HTTP Handler that takes an incoming WebSocket
// connection and proxies it to another server.
type WebSocketProxy struct {
	// director, if non-nil, is a function that may copy additional request
	// headers from the incoming WebSocket connection into the output headers
	// which will be forwarded to another server.
	director func(incoming *http.Request, out http.Header)

	// backend returns the backend URL which the proxy uses to reverse proxy
	// the incoming WebSocket connection. Request is the initial incoming and
	// unmodified request.
	backend func(*http.Request) *url.URL
}

// ProxyHandler returns a new http.Handler interface that reverse proxies the
// request to the given target.
func ProxyHandler(target *url.URL) http.Handler { return NewWebSocketProxy(target) }

// NewWebSocketProxy returns a new Websocket reverse proxy that rewrites the
// URL's to the scheme, host and base path provider in target.
func NewWebSocketProxy(target *url.URL) *WebSocketProxy {
	backend := func(r *http.Request) *url.URL {
		// Shallow copy
		u := *target
		u.Fragment = r.URL.Fragment
		u.Path = r.URL.Path
		u.RawQuery = r.URL.RawQuery
		return &u
	}
	return &WebSocketProxy{backend: backend}
}

//nolint:gocognit
func (w *WebSocketProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if w.backend == nil {
		http.Error(rw, "WebSocketProxy: backend is not defined", http.StatusInternalServerError)
		return
	}

	backendURL := w.backend(r)
	if backendURL == nil {
		http.Error(rw, "WebSocketProxy: backend URL is nil", http.StatusInternalServerError)
		return
	}

	// Forward all incoming headers to the backend except hop-by-hop headers
	// (RFC 7230 §6.1) and WebSocket handshake headers managed by the dialer.
	// Per RFC 7230, also strip any header named by Connection tokens.
	connTokens := map[string]bool{}
	for _, v := range r.Header[HopByHopConnection] {
		for _, token := range strings.Split(v, ",") {
			if h := http.CanonicalHeaderKey(strings.TrimSpace(token)); h != "" {
				connTokens[h] = true
			}
		}
	}
	requestHeader := http.Header{}
	for key, values := range r.Header {
		switch key {
		case HopByHopConnection, HopByHopKeepAlive, HopByHopProxyAuth, HopByHopProxyAuthz,
			HopByHopTE, HopByHopTrailer, HopByHopTransferEncoding, HopByHopUpgrade,
			HopByHopProxyConnection, SecWebSocketKey, SecWebSocketVersion, SecWebSocketExtensions:
			continue
		}
		if connTokens[key] {
			continue
		}
		for _, v := range values {
			requestHeader.Add(key, v)
		}
	}
	if r.Host != "" {
		requestHeader.Set(Host, r.Host)
	}

	// Pass X-Forwarded-For headers too, code below is a part of
	// httputil.ReverseProxy. See http://en.wikipedia.org/wiki/X-Forwarded-For
	// for more information
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := r.Header[XForwardedFor]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		requestHeader.Set(XForwardedFor, clientIP)
	}

	// Set the originating protocol of the incoming HTTP request. The SSL might
	// be terminated on our site and because we doing proxy adding this would
	// be helpful for applications on the backend.
	requestHeader.Set(XForwardedProto, "http")
	if r.TLS != nil {
		requestHeader.Set(XForwardedProto, "https")
	}

	// Enable the director to copy any additional headers it desires for
	// forwarding to the remote server.
	if w.director != nil {
		w.director(r, requestHeader)
	}

	// HTTP/2 Extended CONNECT (RFC 8441) — raw bidirectional tunnel.
	if r.ProtoMajor >= 2 && r.Method == http.MethodConnect {
		w.serveH2Tunnel(rw, r, backendURL, requestHeader)
		return
	}

	w.serveH1(rw, r, backendURL, requestHeader)
}

// serveH1 handles the traditional HTTP/1.1 WebSocket upgrade path.
func (w *WebSocketProxy) serveH1(rw http.ResponseWriter, r *http.Request, backendURL *url.URL, requestHeader http.Header) {
	ctx := r.Context()

	// Dial the backend first so we can relay errors before upgrading the client.
	connBackend, resp, err := websocket.Dial(ctx, backendURL.String(), &websocket.DialOptions{
		HTTPHeader: requestHeader,
	})
	if err != nil {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf("WebSocketProxy: couldn't dial to remote backend")
		if resp != nil {
			if copyErr := copyResponse(rw, resp); copyErr != nil {
				Logger.With(slogger.Field{Key: "error", Value: copyErr}).Errorf("WebSocketProxy: couldn't write response after failed remote backend handshake")
			}
		} else {
			http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		}
		return
	}
	defer connBackend.CloseNow() //nolint:errcheck

	// Accept the client-side WebSocket upgrade.
	connPub, err := websocket.Accept(rw, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
		Subprotocols:       subprotocolsFromResponse(resp),
	})
	if err != nil {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf("WebSocketProxy: couldn't upgrade websocket connection")
		return
	}
	defer connPub.CloseNow() //nolint:errcheck

	// Bidirectional relay.
	errClient := make(chan error, 1)
	errBackend := make(chan error, 1)

	go replicateConn(ctx, connPub, connBackend, errClient)
	go replicateConn(ctx, connBackend, connPub, errBackend)

	var message string
	select {
	case err = <-errClient:
		message = "WebSocketProxy: Error when copying from backend to client: %v"
	case err = <-errBackend:
		message = "WebSocketProxy: Error when copying from client to backend: %v"
	}

	var closeErr websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code == websocket.StatusAbnormalClosure {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf(message, err)
	}
}

// serveH2Tunnel handles HTTP/2 Extended CONNECT (RFC 8441) by creating
// a raw bidirectional tunnel between the h2 stream and a backend h1 WebSocket.
func (w *WebSocketProxy) serveH2Tunnel(rw http.ResponseWriter, r *http.Request, backendURL *url.URL, requestHeader http.Header) {
	ctx := r.Context()

	connBackend, resp, err := websocket.Dial(ctx, backendURL.String(), &websocket.DialOptions{
		HTTPHeader: requestHeader,
	})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf("WebSocketProxy: couldn't dial to remote backend (h2 tunnel)")
		http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	backendNetConn := websocket.NetConn(ctx, connBackend, websocket.MessageBinary)
	defer backendNetConn.Close()

	rc := http.NewResponseController(rw)
	if err := rc.EnableFullDuplex(); err != nil {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf("WebSocketProxy: EnableFullDuplex failed")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		Logger.With(slogger.Field{Key: "error", Value: err}).Errorf("WebSocketProxy: flush failed")
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(backendNetConn, r.Body)
	}()
	_, _ = io.Copy(rw, backendNetConn)
	<-done
}

func replicateConn(ctx context.Context, dst, src *websocket.Conn, errc chan error) {
	for {
		msgType, msg, err := src.Read(ctx)
		if err != nil {
			errc <- err
			dst.Close(websocket.StatusNormalClosure, "")
			break
		}
		err = dst.Write(ctx, msgType, msg)
		if err != nil {
			errc <- err
			break
		}
	}
}

func subprotocolsFromResponse(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	if proto := resp.Header.Get(SecWebSocketProtocol); proto != "" {
		return []string{proto}
	}
	return nil
}

func copyResponse(rw http.ResponseWriter, resp *http.Response) error {
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	defer resp.Body.Close()

	_, err := io.Copy(rw, resp.Body)
	return err
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
