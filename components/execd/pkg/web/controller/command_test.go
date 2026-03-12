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

package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/alibaba/opensandbox/execd/pkg/runtime"
	"github.com/alibaba/opensandbox/execd/pkg/web/model"
)

func TestBuildExecuteCommandRequestForwardsEnvs(t *testing.T) {
	ctrl := &CodeInterpretingController{}
	envs := map[string]string{"FOO": "bar", "BAZ": "qux"}
	req := model.RunCommandRequest{
		Command: "echo hi",
		Cwd:     "/tmp",
		Envs:    envs,
	}

	execReq := ctrl.buildExecuteCommandRequest(req)

	if execReq.Language != runtime.Command {
		t.Fatalf("expected runtime.Command, got %s", execReq.Language)
	}
	if !reflect.DeepEqual(execReq.Envs, envs) {
		t.Fatalf("expected envs to be forwarded, got %#v", execReq.Envs)
	}
	if execReq.Cwd != "/tmp" {
		t.Fatalf("expected Cwd to be forwarded, got %s", execReq.Cwd)
	}
}

func TestBuildExecuteCommandRequestForwardsEnvsBackground(t *testing.T) {
	ctrl := &CodeInterpretingController{}
	envs := map[string]string{"FOO": "bar"}
	req := model.RunCommandRequest{
		Command:    "echo hi",
		Background: true,
		Envs:       envs,
	}

	execReq := ctrl.buildExecuteCommandRequest(req)

	if execReq.Language != runtime.BackgroundCommand {
		t.Fatalf("expected runtime.BackgroundCommand, got %s", execReq.Language)
	}
	if !reflect.DeepEqual(execReq.Envs, envs) {
		t.Fatalf("expected envs to be forwarded, got %#v", execReq.Envs)
	}
}

func setupCommandController(method, path string) (*CodeInterpretingController, *httptest.ResponseRecorder) {
	ctx, w := newTestContext(method, path, nil)
	ctrl := NewCodeInterpretingController(ctx)
	return ctrl, w
}

func TestGetCommandStatus_MissingID(t *testing.T) {
	ctrl, w := setupCommandController(http.MethodGet, "/command/status/")

	ctrl.GetCommandStatus()

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp model.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Code != model.ErrorCodeInvalidRequest {
		t.Fatalf("unexpected error code: %s", resp.Code)
	}
	if resp.Message != "missing command execution id" {
		t.Fatalf("unexpected message: %s", resp.Message)
	}
}

func TestGetBackgroundCommandOutput_MissingID(t *testing.T) {
	ctrl, w := setupCommandController(http.MethodGet, "/command/logs/")

	ctrl.GetBackgroundCommandOutput()

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp model.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Code != model.ErrorCodeMissingQuery {
		t.Fatalf("unexpected error code: %s", resp.Code)
	}
	if resp.Message != "missing command execution id" {
		t.Fatalf("unexpected message: %s", resp.Message)
	}
}
