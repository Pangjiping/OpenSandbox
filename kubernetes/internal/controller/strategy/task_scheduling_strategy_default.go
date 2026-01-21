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

package strategy

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/strategicpatch"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/api/v1alpha1"
	api "github.com/alibaba/OpenSandbox/sandbox-k8s/pkg/task-executor"
)

// DefaultTaskSchedulingStrategy implements the default task scheduling strategy.
type DefaultTaskSchedulingStrategy struct{}

// NewDefaultTaskSchedulingStrategy creates a new default task scheduling strategy.
func NewDefaultTaskSchedulingStrategy() *DefaultTaskSchedulingStrategy {
	return &DefaultTaskSchedulingStrategy{}
}

// NeedTaskScheduling determines whether task scheduling is needed based on TaskTemplate.
func (s *DefaultTaskSchedulingStrategy) NeedTaskScheduling(batchSbx *sandboxv1alpha1.BatchSandbox) bool {
	return batchSbx.Spec.TaskTemplate != nil
}

// GenerateTaskSpecs generates task specifications for all replicas.
func (s *DefaultTaskSchedulingStrategy) GenerateTaskSpecs(batchSbx *sandboxv1alpha1.BatchSandbox) ([]*api.Task, error) {
	ret := make([]*api.Task, *batchSbx.Spec.Replicas)
	for idx := range int(*batchSbx.Spec.Replicas) {
		task, err := s.getTaskSpec(batchSbx, idx)
		if err != nil {
			return ret, err
		}
		ret[idx] = task
	}
	return ret, nil
}

// getTaskSpec generates a single task specification for the given index.
// It applies ShardTaskPatches if available, otherwise uses the base TaskTemplate.
func (s *DefaultTaskSchedulingStrategy) getTaskSpec(batchSbx *sandboxv1alpha1.BatchSandbox, idx int) (*api.Task, error) {
	task := &api.Task{
		Name: fmt.Sprintf("%s-%d", batchSbx.Name, idx),
	}
	if len(batchSbx.Spec.ShardTaskPatches) > 0 && idx < len(batchSbx.Spec.ShardTaskPatches) {
		taskTemplate := batchSbx.Spec.TaskTemplate.DeepCopy()
		cloneBytes, _ := json.Marshal(taskTemplate)
		patch := batchSbx.Spec.ShardTaskPatches[idx]
		modified, err := strategicpatch.StrategicMergePatch(cloneBytes, patch.Raw, &sandboxv1alpha1.TaskTemplateSpec{})
		if err != nil {
			return nil, fmt.Errorf("batchsandbox: failed to merge patch raw %s, idx %d, err %w", patch.Raw, idx, err)
		}
		newTaskTemplate := &sandboxv1alpha1.TaskTemplateSpec{}
		if err = json.Unmarshal(modified, newTaskTemplate); err != nil {
			return nil, fmt.Errorf("batchsandbox: failed to unmarshal %s to TaskTemplateSpec, idx %d, err %w", modified, idx, err)
		}
		task.Process = &api.Process{
			Command:        newTaskTemplate.Spec.Process.Command,
			Args:           newTaskTemplate.Spec.Process.Args,
			Env:            newTaskTemplate.Spec.Process.Env,
			WorkingDir:     newTaskTemplate.Spec.Process.WorkingDir,
			TimeoutSeconds: batchSbx.Spec.TaskTemplate.Spec.TimeoutSeconds,
		}
	} else if batchSbx.Spec.TaskTemplate != nil && batchSbx.Spec.TaskTemplate.Spec.Process != nil {
		task.Process = &api.Process{
			Command:        batchSbx.Spec.TaskTemplate.Spec.Process.Command,
			Args:           batchSbx.Spec.TaskTemplate.Spec.Process.Args,
			Env:            batchSbx.Spec.TaskTemplate.Spec.Process.Env,
			WorkingDir:     batchSbx.Spec.TaskTemplate.Spec.Process.WorkingDir,
			TimeoutSeconds: batchSbx.Spec.TaskTemplate.Spec.TimeoutSeconds,
		}
	}
	return task, nil
}
