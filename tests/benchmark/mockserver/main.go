/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

func main() {
	lifecycleAddr := flag.String("lifecycle-addr", "127.0.0.1:18080", "lifecycle API listen address")
	execdAddr := flag.String("execd-addr", "127.0.0.1:18081", "execd API listen address")
	configPath := flag.String("config", "", "path to a mock server config JSON file")
	statsWindowSec := flag.Int("stats-window-sec", DefaultStatsWindowSec, "per-API QPS history window in seconds")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	host, port, err := splitHostPort(*execdAddr)
	if err != nil {
		log.Fatalf("invalid execd addr: %v", err)
	}
	mock := newMockServer(cfg, host, port, *statsWindowSec)

	lifecycleMux := http.NewServeMux()
	lifecycleMux.HandleFunc("/", mock.handleLifecycle)
	execdMux := http.NewServeMux()
	execdMux.HandleFunc("/", mock.handleExecd)

	lifecycleSrv := &http.Server{
		Addr:              *lifecycleAddr,
		Handler:           lifecycleMux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	execdSrv := &http.Server{
		Addr:              *execdAddr,
		Handler:           execdMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("mock lifecycle server listening on http://%s", *lifecycleAddr)
	log.Printf("mock execd server listening on http://%s", *execdAddr)

	errCh := make(chan error, 2)
	go func() { errCh <- lifecycleSrv.ListenAndServe() }()
	go func() { errCh <- execdSrv.ListenAndServe() }()
	log.Fatal(<-errCh)
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	return host, port, nil
}
