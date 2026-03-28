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
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/dialer"
	"github.com/alibaba/opensandbox/egress/pkg/iptables"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// Start runs the cleartext HTTP transparent proxy until ctx is cancelled.
func Start(ctx context.Context, cfg Config) error {
	if !cfg.Enabled {
		return nil
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return err
	}
	proxyPort, err := cfg.ListenPort()
	if err != nil {
		_ = ln.Close()
		return err
	}
	if err := iptables.SetupHTTPRedirect(proxyPort); err != nil {
		_ = ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	srv := &server{
		inject: cfg.Inject,
		dialer: dialer.Marked(60 * time.Second),
	}

	log.Infof("[http] transparent proxy listening on %s (iptables redirect tcp/80 -> local)", cfg.ListenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go srv.handleConn(conn)
	}
}

type server struct {
	inject map[string]string
	dialer *net.Dialer
}

func (s *server) handleConn(client net.Conn) {
	defer client.Close()

	orig, err := getOriginalDst(client)
	if err != nil {
		log.Warnf("[http] original dst: %v", err)
		return
	}
	s.forwardHTTP(client, orig)
}

// forwardHTTP proxies cleartext HTTP from client to orig (host:port), injecting s.inject headers on each request.
func (s *server) forwardHTTP(client net.Conn, orig netip.AddrPort) {
	upstreamAddr := net.JoinHostPort(orig.Addr().String(), strconv.Itoa(int(orig.Port())))

	up, err := s.dialer.Dial("tcp", upstreamAddr)
	if err != nil {
		log.Warnf("[http] dial upstream %s: %v", upstreamAddr, err)
		return
	}
	defer up.Close()

	brClient := bufio.NewReader(client)
	brUp := bufio.NewReader(up)

	for {
		req, err := http.ReadRequest(brClient)
		if err != nil {
			if err != io.EOF {
				log.Warnf("[http] read request: %v", err)
			}
			return
		}
		for k, v := range s.inject {
			req.Header.Set(k, v)
		}
		req.RequestURI = ""

		if err := req.Write(up); err != nil {
			log.Warnf("[http] write request to upstream: %v", err)
			return
		}
		if req.Body != nil {
			if _, err := io.Copy(up, req.Body); err != nil {
				return
			}
			if err := req.Body.Close(); err != nil {
				return
			}
		}

		resp, err := http.ReadResponse(brUp, req)
		if err != nil {
			log.Warnf("[http] read response: %v", err)
			return
		}
		if err := resp.Write(client); err != nil {
			log.Warnf("[http] write response to client: %v", err)
			return
		}

		if resp.Close || req.Close {
			return
		}
	}
}
