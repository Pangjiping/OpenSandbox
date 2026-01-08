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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alibaba/OpenSandbox/sandbox-k8s/api/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/config"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/types"
	api "github.com/alibaba/OpenSandbox/sandbox-k8s/pkg/task-executor"
)

// MockTaskManager implements manager.TaskManager for testing
type MockTaskManager struct {
	tasks map[string]*types.Task
	err   error
}

func NewMockTaskManager() *MockTaskManager {
	return &MockTaskManager{
		tasks: make(map[string]*types.Task),
	}
}

func (m *MockTaskManager) Create(ctx context.Context, task *types.Task) (*types.Task, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.tasks[task.Name] = task
	return task, nil
}

func (m *MockTaskManager) Sync(ctx context.Context, desired []*types.Task) ([]*types.Task, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.tasks = make(map[string]*types.Task)
	var result []*types.Task
	for _, t := range desired {
		m.tasks[t.Name] = t
		result = append(result, t)
	}
	return result, nil
}

func (m *MockTaskManager) Get(ctx context.Context, id string) (*types.Task, error) {
	if m.err != nil {
		return nil, m.err
	}
	if t, ok := m.tasks[id]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("not found")
}

func (m *MockTaskManager) List(ctx context.Context) ([]*types.Task, error) {
	if m.err != nil {
		return nil, m.err
	}
	var list []*types.Task
	for _, t := range m.tasks {
		list = append(list, t)
	}
	return list, nil
}

func (m *MockTaskManager) Delete(ctx context.Context, id string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.tasks, id)
	return nil
}

func (m *MockTaskManager) Start(ctx context.Context) {}
func (m *MockTaskManager) Stop()                     {}

func TestHandler_Health(t *testing.T) {
	cfg := &config.Config{}
	h := NewHandler(NewMockTaskManager(), cfg)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.Health(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Health returned status %d", w.Code)
	}
}

func TestHandler_CreateTask(t *testing.T) {
	mgr := NewMockTaskManager()
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)

	task := api.Task{
		Name: "test-task",
		Spec: v1alpha1.TaskSpec{
			Process: &v1alpha1.ProcessTask{
				Command: []string{"echo"},
			},
		},
	}
	body, _ := json.Marshal(task)

	req := httptest.NewRequest("POST", "/tasks", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.CreateTask(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("CreateTask returned status %d", w.Code)
	}

	if _, ok := mgr.tasks["test-task"]; !ok {
		t.Error("Task was not created in manager")
	}
}

func TestHandler_GetTask(t *testing.T) {
	mgr := NewMockTaskManager()
	mgr.tasks["test-task"] = &types.Task{Name: "test-task"}
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)

	router := NewRouter(h)
	req := httptest.NewRequest("GET", "/tasks/test-task", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("GetTask returned status %d", w.Code)
	}

	var resp api.Task
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Name != "test-task" {
		t.Errorf("GetTask returned name %s", resp.Name)
	}
}

func TestHandler_DeleteTask(t *testing.T) {
	mgr := NewMockTaskManager()
	mgr.tasks["test-task"] = &types.Task{Name: "test-task"}
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)
	router := NewRouter(h)

	req := httptest.NewRequest("DELETE", "/tasks/test-task", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("DeleteTask returned status %d", w.Code)
	}

	if _, ok := mgr.tasks["test-task"]; ok {
		t.Error("Task was not deleted from manager")
	}
}

func TestHandler_ListTasks(t *testing.T) {
	mgr := NewMockTaskManager()
	mgr.tasks["task-1"] = &types.Task{Name: "task-1"}
	mgr.tasks["task-2"] = &types.Task{Name: "task-2"}
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)

	req := httptest.NewRequest("GET", "/getTasks", nil)
	w := httptest.NewRecorder()

	h.ListTasks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("ListTasks returned status %d", w.Code)
	}

	var resp []api.Task
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp) != 2 {
		t.Errorf("ListTasks returned %d tasks, want 2", len(resp))
	}
}

func TestHandler_SyncTasks(t *testing.T) {
	mgr := NewMockTaskManager()
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)

	tasks := []api.Task{
		{Name: "task-1", Spec: v1alpha1.TaskSpec{Process: &v1alpha1.ProcessTask{}}},
	}
	body, _ := json.Marshal(tasks)

	req := httptest.NewRequest("POST", "/setTasks", bytes.NewReader(body))
	w := httptest.NewRecorder()

	h.SyncTasks(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("SyncTasks returned status %d", w.Code)
	}

	if _, ok := mgr.tasks["task-1"]; !ok {
		t.Error("Task was not synced to manager")
	}
}

func TestHandler_Errors(t *testing.T) {
	mgr := NewMockTaskManager()
	mgr.err = errors.New("mock error")
	cfg := &config.Config{}
	h := NewHandler(mgr, cfg)

	// Create fail
	task := api.Task{Name: "fail"}
	body, _ := json.Marshal(task)
	req := httptest.NewRequest("POST", "/tasks", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.CreateTask(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("CreateTask should fail with 500, got %d", w.Code)
	}
}
