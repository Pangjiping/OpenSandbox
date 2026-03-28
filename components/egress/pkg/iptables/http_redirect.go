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

package iptables

import (
	"fmt"
	"os/exec"
	"strconv"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
)

// SetupHTTPRedirect installs OUTPUT nat rules: tcp dport 80 -> local proxyPort, with mark bypass
// and loopback destination exemption. Requires CAP_NET_ADMIN.
func SetupHTTPRedirect(proxyPort int) error {
	targetPort := strconv.Itoa(proxyPort)
	log.Infof("installing iptables HTTP redirect: OUTPUT tcp dport 80 -> %s (mark %s bypass)", targetPort, constants.MarkHex)

	// Avoid redirecting traffic already destined to loopback (prevents loops on local :80).
	rules := [][]string{
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.0/8", "--dport", "80", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-m", "mark", "--mark", constants.MarkHex, "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", targetPort},
		{"ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-d", "::1", "--dport", "80", "-j", "RETURN"},
		{"ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-m", "mark", "--mark", constants.MarkHex, "-j", "RETURN"},
		{"ip6tables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", targetPort},
	}
	for _, args := range rules {
		if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables http redirect: %v (output: %s)", err, output)
		}
	}
	log.Infof("iptables HTTP redirect installed successfully")
	return nil
}
