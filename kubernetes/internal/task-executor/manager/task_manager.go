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

package manager

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/config"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/runtime"
	store "github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/storage"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/task-executor/types"
)

const (
	// Maximum number of concurrent tasks (enforcing single task limitation)
	maxConcurrentTasks = 1
)

type taskManager struct {
	mu    sync.RWMutex
	tasks map[string]*types.Task // name -> task

	store    store.TaskStore
	executor runtime.Executor
	config   *config.Config

	// stopping tracks tasks that are currently being stopped.
	// This prevents duplicate Stop calls and status rollback during async stop.
	stopping map[string]bool

	// Reconcile loop control
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewTaskManager creates a new task manager instance.
func NewTaskManager(cfg *config.Config, taskStore store.TaskStore, exec runtime.Executor) (TaskManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if taskStore == nil {
		return nil, fmt.Errorf("task store cannot be nil")
	}
	if exec == nil {
		return nil, fmt.Errorf("executor cannot be nil")
	}

	return &taskManager{
		tasks:    make(map[string]*types.Task),
		store:    taskStore,
		executor: exec,
		config:   cfg,
		stopping: make(map[string]bool),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}, nil
}

// isTaskActive checks if the task is counting towards the concurrency limit.
// A task is active if it is NOT marked for deletion AND NOT in a terminated state.
func (m *taskManager) isTaskActive(task *types.Task) bool {
	if task == nil {
		return false
	}
	if task.DeletionTimestamp != nil {
		return false
	}
	state := task.Status.State
	return state == types.TaskStatePending || state == types.TaskStateRunning
}

// countActiveTasks counts tasks that are active (not deleted AND not terminated).
// Must be called with lock held.
func (m *taskManager) countActiveTasks() int {
	count := 0
	for _, task := range m.tasks {
		if m.isTaskActive(task) {
			count++
		}
	}
	return count
}

// Create creates a new task and starts execution.
func (m *taskManager) Create(ctx context.Context, task *types.Task) (*types.Task, error) {
	if task == nil {
		return nil, fmt.Errorf("task cannot be nil")
	}
	if task.Name == "" {
		return nil, fmt.Errorf("task name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if task already exists
	if _, exists := m.tasks[task.Name]; exists {
		return nil, fmt.Errorf("task %s already exists", task.Name)
	}

	// Enforce single task limitation using real-time count
	if m.countActiveTasks() >= maxConcurrentTasks {
		return nil, fmt.Errorf("maximum concurrent tasks (%d) reached, cannot create new task", maxConcurrentTasks)
	}

	// Persist task to store
	if err := m.store.Create(ctx, task); err != nil {
		return nil, fmt.Errorf("failed to persist task: %w", err)
	}

	// Start task execution
	if err := m.executor.Start(ctx, task); err != nil {
		// Rollback - delete from store
		if delErr := m.store.Delete(ctx, task.Name); delErr != nil {
			klog.ErrorS(delErr, "failed to rollback task creation", "name", task.Name)
		}
		return nil, fmt.Errorf("failed to start task: %w", err)
	}

	// Inspect immediately to populate status (Running/Waiting) so API response is not empty
	if status, err := m.executor.Inspect(ctx, task); err == nil {
		task.Status = *status
		// Persist the PID and initial status
		if err := m.store.Update(ctx, task); err != nil {
			klog.ErrorS(err, "failed to persist initial task status", "name", task.Name)
		}
	} else {
		klog.ErrorS(err, "failed to inspect task after start", "name", task.Name)
	}

	// Safety fallback: Ensure task has a state
	if task.Status.State == "" {
		task.Status.State = types.TaskStatePending
	}

	// Add to memory
	m.tasks[task.Name] = task

	klog.InfoS("task created successfully", "name", task.Name)
	return task, nil
}

// Sync synchronizes the current task list with the desired state.
// It deletes tasks not in the desired list and creates new ones.
// Returns the current task list and any errors encountered during sync.
func (m *taskManager) Sync(ctx context.Context, desired []*types.Task) ([]*types.Task, error) {
	if desired == nil {
		return nil, fmt.Errorf("desired task list cannot be nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Build desired task map
	desiredMap := make(map[string]*types.Task)
	for _, task := range desired {
		if task != nil && task.Name != "" {
			desiredMap[task.Name] = task
		}
	}

	// Collect errors during sync
	var syncErrors []error

	// Delete tasks not in desired list
	for name, task := range m.tasks {
		if _, ok := desiredMap[name]; !ok {
			if err := m.softDeleteLocked(ctx, task); err != nil {
				klog.ErrorS(err, "failed to delete task during sync", "name", name)
				syncErrors = append(syncErrors, fmt.Errorf("failed to delete task %s: %w", name, err))
			}
		}
	}

	// Create new tasks
	for name, task := range desiredMap {
		if _, exists := m.tasks[name]; !exists {
			if err := m.createTaskLocked(ctx, task); err != nil {
				klog.ErrorS(err, "failed to create task during sync", "name", name)
				syncErrors = append(syncErrors, fmt.Errorf("failed to create task %s: %w", name, err))
			}
		}
	}

	// Return current task list with aggregated errors
	if len(syncErrors) > 0 {
		return m.listTasksLocked(), errors.Join(syncErrors...)
	}
	return m.listTasksLocked(), nil
}

// Get retrieves a task by name.
func (m *taskManager) Get(ctx context.Context, name string) (*types.Task, error) {
	if name == "" {
		return nil, fmt.Errorf("task name cannot be empty")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	task, exists := m.tasks[name]
	if !exists {
		return nil, fmt.Errorf("task %s not found", name)
	}

	return task, nil
}

// List returns all tasks.
func (m *taskManager) List(ctx context.Context) ([]*types.Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.listTasksLocked(), nil
}

// Delete removes a task by marking it for deletion (soft delete).
// The reconcile loop will handle the actual stopping and removal.
func (m *taskManager) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("task name cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	task, exists := m.tasks[name]
	if !exists {
		return nil
	}

	return m.softDeleteLocked(ctx, task)
}

// softDeleteLocked marks a task for deletion without acquiring the lock.
func (m *taskManager) softDeleteLocked(ctx context.Context, task *types.Task) error {
	if task.DeletionTimestamp != nil {
		return nil // Already marked
	}

	now := time.Now()
	task.DeletionTimestamp = &now

	if err := m.store.Update(ctx, task); err != nil {
		return fmt.Errorf("failed to mark task for deletion: %w", err)
	}

	klog.InfoS("task marked for deletion", "name", task.Name)
	return nil
}

// Start initializes the manager, loads tasks from store, and starts the reconcile loop.
func (m *taskManager) Start(ctx context.Context) {
	klog.InfoS("starting task manager")

	// Recover tasks from store
	if err := m.recoverTasks(ctx); err != nil {
		klog.ErrorS(err, "failed to recover tasks from store")
	}

	// Start reconcile loop
	go m.reconcileLoop(ctx)

	klog.InfoS("task manager started")
}

// Stop stops the reconcile loop and cleans up resources.
func (m *taskManager) Stop() {
	klog.InfoS("stopping task manager")
	close(m.stopCh)
	<-m.doneCh
	klog.InfoS("task manager stopped")
}

// createTaskLocked creates a task without acquiring the lock (must be called with lock held).
func (m *taskManager) createTaskLocked(ctx context.Context, task *types.Task) error {
	if task == nil || task.Name == "" {
		return fmt.Errorf("invalid task")
	}

	// Check if already exists
	if _, exists := m.tasks[task.Name]; exists {
		return fmt.Errorf("task %s already exists", task.Name)
	}

	// Enforce single task limitation using real-time count
	if m.countActiveTasks() >= maxConcurrentTasks {
		return fmt.Errorf("maximum concurrent tasks (%d) reached, cannot create new task", maxConcurrentTasks)
	}

	// Persist to store
	if err := m.store.Create(ctx, task); err != nil {
		return fmt.Errorf("failed to persist task: %w", err)
	}

	// Start execution
	if err := m.executor.Start(ctx, task); err != nil {
		// Rollback
		m.store.Delete(ctx, task.Name)
		return fmt.Errorf("failed to start task: %w", err)
	}

	// Inspect immediately to populate status (Running/Waiting) so API response is not empty
	if status, err := m.executor.Inspect(ctx, task); err == nil {
		task.Status = *status
		// Persist the PID and initial status
		if err := m.store.Update(ctx, task); err != nil {
			klog.ErrorS(err, "failed to persist initial task status", "name", task.Name)
		}
	} else {
		klog.ErrorS(err, "failed to inspect task after start", "name", task.Name)
	}

	// Add to memory
	m.tasks[task.Name] = task
	return nil
}

// listTasksLocked returns all tasks without acquiring the lock (must be called with lock held).
func (m *taskManager) listTasksLocked() []*types.Task {
	tasks := make([]*types.Task, 0, len(m.tasks))
	for _, task := range m.tasks {
		if task != nil {
			tasks = append(tasks, task)
		}
	}
	return tasks
}

// recoverTasks loads tasks from store and recovers their state.
func (m *taskManager) recoverTasks(ctx context.Context) error {
	klog.InfoS("recovering tasks from store")

	tasks, err := m.store.List(ctx)
	if err != nil {
		return fmt.Errorf("failed to list tasks from store: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, task := range tasks {
		if task == nil {
			continue
		}

		// Inspect task to get current status
		status, err := m.executor.Inspect(ctx, task)
		if err != nil {
			klog.ErrorS(err, "failed to inspect task during recovery", "name", task.Name)
			continue
		}

		// Update task status
		task.Status = *status

		// Add to memory
		m.tasks[task.Name] = task

		klog.InfoS("recovered task", "name", task.Name, "state", task.Status.State, "deleting", task.DeletionTimestamp != nil)
	}

	klog.InfoS("task recovery completed", "count", len(m.tasks))
	return nil
}

// reconcileLoop periodically synchronizes task states.
func (m *taskManager) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.ReconcileInterval)
	defer ticker.Stop()
	defer close(m.doneCh)

	for {
		select {
		case <-ticker.C:
			m.reconcileTasks(ctx)
		case <-m.stopCh:
			klog.InfoS("reconcile loop stopped")
			return
		case <-ctx.Done():
			klog.InfoS("reconcile loop context canceled")
			return
		}
	}
}

// reconcileTasks updates the status of all tasks and handles deletion.
func (m *taskManager) reconcileTasks(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var tasksToDelete []string

	for name, task := range m.tasks {
		if task == nil {
			continue
		}
		status, err := m.executor.Inspect(ctx, task)
		if err != nil {
			klog.ErrorS(err, "failed to inspect task", "name", name)
			continue
		}
		state := status.State

		// Determine if we should stop the task
		shouldStop := false
		stopReason := ""

		if task.DeletionTimestamp != nil && !m.stopping[name] {
			if !isTerminalState(state) {
				shouldStop = true
				stopReason = "deletion requested"
			}
		} else if state == types.TaskStateTimeout && !m.stopping[name] {
			shouldStop = true
			stopReason = "timeout exceeded"
		}

		if shouldStop {
			klog.InfoS("stopping task", "name", name, "reason", stopReason)
			m.stopping[name] = true

			// Async stop to avoid blocking the reconcile loop
			go func(t *types.Task, taskName string) {
				defer func() {
					m.mu.Lock()
					delete(m.stopping, taskName)
					m.mu.Unlock()
				}()

				if err := m.executor.Stop(ctx, t); err != nil {
					klog.ErrorS(err, "failed to stop task", "name", taskName)
				}
				klog.InfoS("task stopped", "name", taskName)
			}(task, name)
		}

		// Determine if we can finalize deletion
		if task.DeletionTimestamp != nil && isTerminalState(state) {
			klog.InfoS("task terminated, finalizing deletion", "name", name)
			tasksToDelete = append(tasksToDelete, name)
		}

		// Update status only if not stopping (prevent status rollback during async stop)
		if !m.stopping[name] {
			if !reflect.DeepEqual(task.Status, *status) {
				task.Status = *status
				if err := m.store.Update(ctx, task); err != nil {
					klog.ErrorS(err, "failed to update task status in store", "name", name)
				}
			}
		}
	}

	// Finalize deletions
	for _, name := range tasksToDelete {
		if _, exists := m.tasks[name]; !exists {
			continue
		}

		if err := m.store.Delete(ctx, name); err != nil {
			klog.ErrorS(err, "failed to delete task from store", "name", name)
			continue
		}

		delete(m.tasks, name)
		delete(m.stopping, name)
		klog.InfoS("task deleted successfully", "name", name)
	}
}

// isTerminalState returns true if the task will not transition to another state.
func isTerminalState(state types.TaskState) bool {
	return state == types.TaskStateSucceeded ||
		state == types.TaskStateFailed ||
		state == types.TaskStateNotFound
}
