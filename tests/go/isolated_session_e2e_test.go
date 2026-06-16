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

package e2e

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	opensandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createIsolatedTestSandbox(t *testing.T) (context.Context, *opensandbox.Sandbox) {
	t.Helper()
	config := connectionConfigForStreaming(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	sb, err := opensandbox.CreateSandbox(ctx, config, opensandbox.SandboxCreateOptions{
		Image:      getSandboxImage(),
		Extensions: map[string]string{"bootstrap.execd.isolation": "enable"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { sb.Kill(context.Background()) })

	caps, err := sb.IsolationCapabilities(ctx)
	require.NoError(t, err)
	t.Logf("Isolation capabilities: available=%v isolator=%s version=%s message=%s",
		caps.Available, caps.Isolator, caps.Version, caps.Message)
	if !caps.Available {
		t.Fatalf("Isolation NOT available: %s", caps.Message)
	}

	return ctx, sb
}

func TestIsolationCapabilities(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)
	caps, err := sb.IsolationCapabilities(ctx)
	require.NoError(t, err)
	assert.True(t, caps.Available)
}

func TestIsolationSessionLifecycle(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, session.SessionID())

	state, err := session.Get(ctx)
	require.NoError(t, err)
	assert.Equal(t, "active", state.Status)

	err = session.Delete(ctx)
	require.NoError(t, err)
}

func TestIsolationRunEcho(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	exec, err := session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "echo hello-isolation"}, nil)
	require.NoError(t, err)
	assert.Contains(t, exec.Text(), "hello-isolation")
}

func TestIsolationPIDIsolation(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	exec, err := session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "echo $$"}, nil)
	require.NoError(t, err)
	pid, err := strconv.Atoi(strings.TrimSpace(exec.Text()))
	require.NoError(t, err)
	assert.LessOrEqual(t, pid, 2, "expected PID 1 or 2 in namespace, got %d", pid)
}

func TestIsolationRunWithEnvs(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	exec, err := session.Run(ctx, opensandbox.IsolatedRunRequest{
		Code: "echo $MY_VAR",
		Envs: map[string]string{"MY_VAR": "test-value-42"},
	}, nil)
	require.NoError(t, err)
	assert.Contains(t, exec.Text(), "test-value-42")
}

func TestIsolationSessionStatePersists(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	_, err = session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "export PERSIST_VAR=abc123"}, nil)
	require.NoError(t, err)

	exec, err := session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "echo $PERSIST_VAR"}, nil)
	require.NoError(t, err)
	assert.Contains(t, exec.Text(), "abc123")
}

func TestIsolationTmpIsolation(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	sb.RunCommand(ctx, "mkdir -p /workspace", nil)

	sessionA, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/workspace", Mode: "rw"},
		Profile:   "strict",
	})
	require.NoError(t, err)
	defer sessionA.Delete(ctx)

	sessionB, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/workspace", Mode: "rw"},
		Profile:   "strict",
	})
	require.NoError(t, err)
	defer sessionB.Delete(ctx)

	_, err = sessionA.Run(ctx, opensandbox.IsolatedRunRequest{
		Code: "echo secret > /tmp/isolated_test_file.txt",
	}, nil)
	require.NoError(t, err)

	exec, err := sessionB.Run(ctx, opensandbox.IsolatedRunRequest{
		Code: "cat /tmp/isolated_test_file.txt 2>&1 || echo NOT_FOUND",
	}, nil)
	require.NoError(t, err)
	text := exec.Text()
	assert.True(t, strings.Contains(text, "NOT_FOUND") || strings.Contains(text, "No such file"),
		"expected /tmp isolation, got: %s", text)
}

func TestIsolationRunWithHandlers(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	var collected []string
	handlers := &opensandbox.ExecutionHandlers{
		OnStdout: func(msg opensandbox.OutputMessage) error {
			collected = append(collected, msg.Text)
			return nil
		},
	}

	_, err = session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "echo handler-test"}, handlers)
	require.NoError(t, err)
	assert.Contains(t, strings.Join(collected, ""), "handler-test")
}

func TestIsolationFilesViaRun(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "rw"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	_, err = session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "echo hello-from-sdk > /tmp/hello.txt"}, nil)
	require.NoError(t, err)

	exec, err := session.Run(ctx, opensandbox.IsolatedRunRequest{Code: "cat /tmp/hello.txt"}, nil)
	require.NoError(t, err)
	assert.Contains(t, exec.Text(), "hello-from-sdk")
}

func TestIsolationOverlayMode(t *testing.T) {
	ctx, sb := createIsolatedTestSandbox(t)

	marker := "overlay_marker_file.txt"
	session, err := sb.IsolationCreate(ctx, opensandbox.CreateIsolatedSessionRequest{
		Workspace: opensandbox.IsolatedWorkspaceSpec{Path: "/tmp", Mode: "overlay"},
	})
	require.NoError(t, err)
	defer session.Delete(ctx)

	_, err = session.Run(ctx, opensandbox.IsolatedRunRequest{
		Code: "echo overlay-data > /tmp/" + marker,
	}, nil)
	require.NoError(t, err)

	hostCheck, err := sb.RunCommand(ctx, "cat /tmp/"+marker+" 2>&1 || echo NOT_FOUND", nil)
	require.NoError(t, err)
	text := hostCheck.Text()
	assert.True(t, strings.Contains(text, "NOT_FOUND") || strings.Contains(text, "No such file"),
		"overlay write should not be visible on host, got: %s", text)
}
