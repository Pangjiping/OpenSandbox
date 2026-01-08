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

package config

import (
	"flag"
	"os"
	"time"
)

type Config struct {
	DataDir             string
	ListenAddr          string
	CRISocket           string
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	ReconcileInterval   time.Duration
	EnableSidecarMode   bool
	EnableContainerMode bool
	MainContainerName   string
}

func NewConfig() *Config {
	return &Config{
		DataDir:             "/var/lib/sandbox/tasks",
		ListenAddr:          "0.0.0.0:5758",
		CRISocket:           "/var/run/containerd/containerd.sock",
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		ReconcileInterval:   500 * time.Millisecond,
		EnableContainerMode: false,
		EnableSidecarMode:   false,
		MainContainerName:   "main",
	}
}

func (c *Config) LoadFromEnv() {
	if v := os.Getenv("DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	if v := os.Getenv("CRI_SOCKET"); v != "" {
		c.CRISocket = v
	}
	if v := os.Getenv("ENABLE_CONTAINER_MODE"); v == "true" {
		c.EnableContainerMode = true
	}
	if v := os.Getenv("ENABLE_SIDECAR_MODE"); v == "true" {
		c.EnableSidecarMode = true
	}
	if v := os.Getenv("MAIN_CONTAINER_NAME"); v != "" {
		c.MainContainerName = v
	}
}

func (c *Config) LoadFromFlags() {
	flag.StringVar(&c.DataDir, "data-dir", c.DataDir, "data storage directory")
	flag.StringVar(&c.ListenAddr, "listen-addr", c.ListenAddr, "service listen address")
	flag.StringVar(&c.CRISocket, "cri-socket", c.CRISocket, "CRI socket path for container runner mode")
	flag.BoolVar(&c.EnableContainerMode, "enable-container-mode", c.EnableContainerMode, "enable container runner mode")
	flag.BoolVar(&c.EnableSidecarMode, "enable-sidecar-mode", c.EnableSidecarMode, "enable sidecar runner mode")
	flag.StringVar(&c.MainContainerName, "main-container-name", c.MainContainerName, "main container name")
	flag.Parse()
}
