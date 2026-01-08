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
	"encoding/json"
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/alibaba/OpenSandbox/sandbox-k8s/api/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/config"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/manager"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/types"
	api "github.com/alibaba/OpenSandbox/sandbox-k8s/pkg/task-executor"
)

// ErrorResponse represents a standard error response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Handler struct {
	manager manager.TaskManager
	config  *config.Config
}

func NewHandler(mgr manager.TaskManager, cfg *config.Config) *Handler {
	if mgr == nil {
		klog.Warning("TaskManager is nil, handler may not work properly")
	}
	if cfg == nil {
		klog.Warning("Config is nil, handler may not work properly")
	}
	return &Handler{
		manager: mgr,
		config:  cfg,
	}
}

func (h *Handler) CreateTask(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "task manager not initialized")
		return
	}

	// Parse request body
	var apiTask api.Task
	if err := json.NewDecoder(r.Body).Decode(&apiTask); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Validate task
	if apiTask.Name == "" {
		writeError(w, http.StatusBadRequest, "task name is required")
		return
	}

	// Convert to internal model
	task := h.convertAPIToInternalTask(&apiTask)
	if task == nil {
		writeError(w, http.StatusBadRequest, "failed to convert task")
		return
	}

	// Create task
	created, err := h.manager.Create(r.Context(), task)
	if err != nil {
		klog.ErrorS(err, "failed to create task", "name", apiTask.Name)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create task: %v", err))
		return
	}

	// Convert back to API model
	response := convertInternalToAPITask(created)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

	klog.InfoS("task created via API", "name", apiTask.Name)
}

func (h *Handler) SyncTasks(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "task manager not initialized")
		return
	}

	// Parse request body - array of tasks
	var apiTasks []api.Task
	if err := json.NewDecoder(r.Body).Decode(&apiTasks); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	// Convert to internal model
	desired := make([]*types.Task, 0, len(apiTasks))
	for i := range apiTasks {
		if apiTasks[i].Name == "" {
			continue // Skip invalid tasks
		}
		task := h.convertAPIToInternalTask(&apiTasks[i])
		if task != nil {
			desired = append(desired, task)
		}
	}

	// Sync tasks
	current, err := h.manager.Sync(r.Context(), desired)
	if err != nil {
		klog.ErrorS(err, "failed to sync tasks")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to sync tasks: %v", err))
		return
	}

	// Convert back to API model
	response := make([]api.Task, 0, len(current))
	for _, task := range current {
		if task != nil {
			response = append(response, *convertInternalToAPITask(task))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	klog.InfoS("tasks synced via API", "count", len(response))
}

func (h *Handler) GetTask(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "task manager not initialized")
		return
	}

	// Extract task ID from path
	taskID := r.PathValue("id")
	if taskID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	// Get task
	task, err := h.manager.Get(r.Context(), taskID)
	if err != nil {
		klog.ErrorS(err, "failed to get task", "id", taskID)
		writeError(w, http.StatusNotFound, fmt.Sprintf("task not found: %v", err))
		return
	}

	// Convert to API model
	response := convertInternalToAPITask(task)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) ListTasks(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "task manager not initialized")
		return
	}

	// List all tasks
	tasks, err := h.manager.List(r.Context())
	if err != nil {
		klog.ErrorS(err, "failed to list tasks")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list tasks: %v", err))
		return
	}

	// Convert to API model
	response := make([]api.Task, 0, len(tasks))
	for _, task := range tasks {
		if task != nil {
			response = append(response, *convertInternalToAPITask(task))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Health returns the health status of the task executor
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"status": "healthy",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *Handler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	if h.manager == nil {
		writeError(w, http.StatusInternalServerError, "task manager not initialized")
		return
	}

	// Extract task ID from path
	taskID := r.PathValue("id")
	if taskID == "" {
		writeError(w, http.StatusBadRequest, "task id is required")
		return
	}

	// Delete task
	err := h.manager.Delete(r.Context(), taskID)
	if err != nil {
		klog.ErrorS(err, "failed to delete task", "id", taskID)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete task: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
	klog.InfoS("task deleted via API", "id", taskID)
}

// writeError writes an error response in JSON format.
func writeError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Code:    http.StatusText(code),
		Message: message,
	})
}

// convertAPIToInternalTask converts api.Task to types.Task.
func (h *Handler) convertAPIToInternalTask(apiTask *api.Task) *types.Task {
	if apiTask == nil {
		return nil
	}
	task := &types.Task{
		Name: apiTask.Name,
		Spec: apiTask.Spec,
	}
	// Initialize default status
	task.Status = types.Status{
		State: types.TaskStatePending,
	}

	return task
}

// convertInternalToAPITask converts types.Task to api.Task.
func convertInternalToAPITask(task *types.Task) *api.Task {
	if task == nil {
		return nil
	}

	apiTask := &api.Task{
		Name: task.Name,
		Spec: task.Spec,
	}

	// Map internal Status to v1alpha1.TaskStatus
	apiStatus := v1alpha1.TaskStatus{
		State: v1alpha1.TaskState{},
	}

	switch task.Status.State {
	case types.TaskStatePending:
		apiStatus.State.Waiting = &v1alpha1.TaskStateWaiting{
			Reason: task.Status.Reason,
		}
	case types.TaskStateRunning:
		if task.Status.StartedAt != nil {
			t := metav1.NewTime(*task.Status.StartedAt)
			apiStatus.State.Running = &v1alpha1.TaskStateRunning{
				StartedAt: t,
			}
		} else {
			apiStatus.State.Running = &v1alpha1.TaskStateRunning{}
		}
	case types.TaskStateSucceeded, types.TaskStateFailed:
		term := &v1alpha1.TaskStateTerminated{
			ExitCode: int32(task.Status.ExitCode),
			Reason:   task.Status.Reason,
			Message:  task.Status.Message,
		}
		if task.Status.StartedAt != nil {
			t := metav1.NewTime(*task.Status.StartedAt)
			term.StartedAt = t
		}
		if task.Status.FinishedAt != nil {
			t := metav1.NewTime(*task.Status.FinishedAt)
			term.FinishedAt = t
		}
		apiStatus.State.Terminated = term
	default:
		apiStatus.State.Waiting = &v1alpha1.TaskStateWaiting{
			Reason: "Unknown",
		}
	}

	apiTask.Status = apiStatus
	return apiTask
}
