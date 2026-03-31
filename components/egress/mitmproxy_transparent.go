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
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/iptables"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/mitmproxy"
)

// startMitmproxyTransparentIfEnabled launches Python mitmdump in transparent mode and installs
// iptables when OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT is truthy. No-op when disabled.
func startMitmproxyTransparentIfEnabled(ctx context.Context) error {
	if !constants.IsTruthy(os.Getenv(constants.EnvMitmproxyTransparent)) {
		return nil
	}

	mpPort := constants.EnvIntOrDefault(constants.EnvMitmproxyPort, constants.DefaultMitmproxyPort)
	mpUser := envOrDefault(constants.EnvMitmproxyUser, "mitmproxy")
	mpUID, _, _, err := mitmproxy.LookupUser(mpUser)
	if err != nil {
		return fmt.Errorf("lookup user %q: %w (ensure this user exists in the image)", mpUser, err)
	}

	_, err = mitmproxy.Launch(ctx, mitmproxy.Config{
		ListenPort: mpPort,
		UserName:   mpUser,
		ConfDir:    strings.TrimSpace(os.Getenv(constants.EnvMitmproxyConfDir)),
		ScriptPath: strings.TrimSpace(os.Getenv(constants.EnvMitmproxyScript)),
		ExtraArgs:  strings.TrimSpace(os.Getenv(constants.EnvMitmproxyExtraArgs)),
	})
	if err != nil {
		return fmt.Errorf("start mitmdump: %w", err)
	}

	waitAddr := fmt.Sprintf("127.0.0.1:%d", mpPort)
	if err := mitmproxy.WaitListenPort(waitAddr, 15*time.Second); err != nil {
		return fmt.Errorf("wait listen %s: %w", waitAddr, err)
	}
	if err := iptables.SetupTransparentHTTP(mpPort, mpUID); err != nil {
		return fmt.Errorf("iptables transparent: %w", err)
	}
	log.Infof("mitmproxy: transparent intercept active (OUTPUT tcp 80,443 -> %d; trust mitm CA in clients)", mpPort)
	return nil
}
