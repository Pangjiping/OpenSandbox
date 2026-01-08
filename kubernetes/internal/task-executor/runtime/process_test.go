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

package runtime

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alibaba/OpenSandbox/sandbox-k8s/api/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/config"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/types"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/utils"
	"github.com/stretchr/testify/assert"
)

func setupTestExecutor(t *testing.T) (Executor, string) {
	dataDir := t.TempDir()
	cfg := &config.Config{
		DataDir:           dataDir,
		EnableSidecarMode: false,
	}
	executor, err := NewProcessExecutor(cfg)
	if err != nil {
		t.Fatalf("Failed to create executor: %v", err)
	}
	return executor, dataDir
}

func TestProcessExecutor_Lifecycle(t *testing.T) {
	// Skip if not running on Linux/Unix-like systems where sh is available
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found, skipping process executor test")
	}

	executor, _ := setupTestExecutor(t)
	pExecutor := executor.(*processExecutor)
	ctx := context.Background()

	// 1. Create a task that runs for a while
	task := &types.Task{
		Name: "long-running",
		Spec: v1alpha1.TaskSpec{
			Process: &v1alpha1.ProcessTask{
				Command: []string{"/bin/sh", "-c", "sleep 10"},
			},
		},
	}

	// Create task directory manually (normally handled by store)

	taskDir, err := utils.SafeJoin(pExecutor.rootDir, task.Name)
	assert.Nil(t, err)
	os.MkdirAll(taskDir, 0755)

	// 2. Start
	if err := executor.Start(ctx, task); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// 3. Inspect (Running)
	status, err := executor.Inspect(ctx, task)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if status.State != types.TaskStateRunning {
		t.Errorf("Task should be running, got: %s", status.State)
	}

	// 4. Stop
	if err := executor.Stop(ctx, task); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// 5. Inspect (Terminated)
	// Wait a bit for file to be written
	time.Sleep(100 * time.Millisecond)
	status, err = executor.Inspect(ctx, task)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	// sleep command killed by signal results in non-zero exit code, so it's Failed
	if status.State != types.TaskStateFailed {
		t.Errorf("Task should be failed (terminated), got: %s", status.State)
	}
}

func TestProcessExecutor_ShortLived(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}

	executor, _ := setupTestExecutor(t)
	pExecutor := executor.(*processExecutor)
	ctx := context.Background()

	task := &types.Task{
		Name: "short-lived",
		Spec: v1alpha1.TaskSpec{
			Process: &v1alpha1.ProcessTask{
				Command: []string{"echo", "done"},
			},
		},
	}
	taskDir, err := utils.SafeJoin(pExecutor.rootDir, task.Name)
	assert.Nil(t, err)
	os.MkdirAll(taskDir, 0755)

	if err := executor.Start(ctx, task); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for process to finish
	time.Sleep(200 * time.Millisecond)

	status, err := executor.Inspect(ctx, task)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if status.State != types.TaskStateSucceeded {
		t.Errorf("Task should be succeeded, got: %s", status.State)
	}
	if status.ExitCode != 0 {
		t.Errorf("Exit code should be 0, got %d", status.ExitCode)
	}
}

func TestProcessExecutor_Failure(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}

	executor, _ := setupTestExecutor(t)
	pExecutor := executor.(*processExecutor)
	ctx := context.Background()

	task := &types.Task{
		Name: "failing-task",
		Spec: v1alpha1.TaskSpec{
			Process: &v1alpha1.ProcessTask{
				Command: []string{"/bin/sh", "-c", "exit 1"},
			},
		},
	}
	taskDir, err := utils.SafeJoin(pExecutor.rootDir, task.Name)
	assert.Nil(t, err)
	os.MkdirAll(taskDir, 0755)

	if err := executor.Start(ctx, task); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	status, err := executor.Inspect(ctx, task)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if status.State != types.TaskStateFailed {
		t.Errorf("Task should be failed")
	} else if status.ExitCode != 1 {
		t.Errorf("Exit code should be 1, got %d", status.ExitCode)
	}
}

func TestProcessExecutor_InvalidArgs(t *testing.T) {
	exec, _ := setupTestExecutor(t)
	ctx := context.Background()

	// Nil task
	if err := exec.Start(ctx, nil); err == nil {
		t.Error("Start should fail with nil task")
	}

	// Missing process spec
	task := &types.Task{
		Name: "invalid",
		Spec: v1alpha1.TaskSpec{},
	}
	if err := exec.Start(ctx, task); err == nil {
		t.Error("Start should fail with missing process spec")
	}
}

func TestShellEscape(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{[]string{"echo", "hello"}, "'echo' 'hello'"},
		{[]string{"echo", "hello world"}, "'echo' 'hello world'"},
		{[]string{"foo'bar"}, "'foo'\\''bar'"},
	}

	for _, tt := range tests {
		got := shellEscape(tt.input)
		if got != tt.expected {
			t.Errorf("shellEscape(%v) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewExecutor(t *testing.T) {
	// 1. Container mode + Host Mode
	cfg := &config.Config{
		EnableContainerMode: true,
	}
	e, err := NewExecutor(cfg)
	if err != nil {
		t.Fatalf("NewExecutor(container) failed: %v", err)
	}
	if _, ok := e.(*compositeExecutor); !ok {
		t.Error("NewExecutor should return CompositeExecutor")
	}

	// 2. Process mode only
	cfg = &config.Config{
		EnableContainerMode: false,
		DataDir:             t.TempDir(),
	}
	e, err = NewExecutor(cfg)
	if err != nil {
		t.Fatalf("NewExecutor(process) failed: %v", err)
	}
	if _, ok := e.(*compositeExecutor); !ok {
		t.Error("NewExecutor should return CompositeExecutor")
	}

	// 3. Nil config
	if _, err := NewExecutor(nil); err == nil {
		t.Error("NewExecutor should fail with nil config")
	}
}
