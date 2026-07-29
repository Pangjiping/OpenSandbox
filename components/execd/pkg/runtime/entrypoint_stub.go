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

//go:build !linux

package runtime

import (
	"net"
	"os"

	"github.com/alibaba/opensandbox/execd/pkg/log"
)

// RunInit is a stub for non-Linux platforms. Init mode is Linux-only.
func RunInit(engine interface{ RunListener(net.Listener) error }, addr string, args []string) {
	log.Warn("execd init: not supported on this platform")
	os.Exit(1)
}
