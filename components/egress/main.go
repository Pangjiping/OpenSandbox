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
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/iptables"
)

// Linux MVP: DNS proxy + iptables REDIRECT. No nftables/full isolation yet.
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	policy, err := dnsproxy.LoadPolicyFromEnv()
	if err != nil {
		log.Fatalf("failed to parse network policy: %v", err)
	}
	if policy == nil {
		log.Println("OPENSANDBOX_NETWORK_POLICY empty; skip egress control")
		// Block here to avoid infinite container restart loop in Kubernetes
		// when restartPolicy is Always. As a sidecar, we should keep running.
		<-ctx.Done()
		return
	}

	proxy, err := dnsproxy.New(policy, "")
	if err != nil {
		log.Fatalf("failed to init dns proxy: %v", err)
	}
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("failed to start dns proxy: %v", err)
	}
	log.Println("dns proxy started on 127.0.0.1:15353")

	if err := iptables.SetupRedirect(15353); err != nil {
		log.Fatalf("failed to install iptables redirect: %v", err)
	}
	log.Printf("iptables redirect configured (OUTPUT 53 -> 15353) with SO_MARK bypass for proxy upstream traffic")

	<-ctx.Done()
	log.Println("received shutdown signal; exiting")
	_ = os.Stderr.Sync()
}
