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
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sandboxv1alpha1 "github.com/alibaba/OpenSandbox/sandbox-k8s/apis/sandbox/v1alpha1"
	"github.com/alibaba/OpenSandbox/sandbox-k8s/internal/controller/eviction"
)

func newEvictionTestPod(name string, labels map[string]string, deleting bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels:    labels,
		},
	}
	if deleting {
		now := metav1.NewTime(time.Now())
		pod.DeletionTimestamp = &now
		pod.Finalizers = []string{"test-finalizer"}
	}
	return pod
}

func newEvictionTestReconciler(objs ...runtime.Object) *PoolReconciler {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = sandboxv1alpha1.AddToScheme(scheme)

	clientObjs := make([]corev1.Pod, 0)
	for _, o := range objs {
		if pod, ok := o.(*corev1.Pod); ok {
			clientObjs = append(clientObjs, *pod)
		}
	}

	builder := fake.NewClientBuilder().WithScheme(scheme)
	for _, pod := range clientObjs {
		p := pod
		builder = builder.WithObjects(&p)
	}
	c := builder.Build()

	return &PoolReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: record.NewFakeRecorder(10),
	}
}

func TestFilterEvictingPods(t *testing.T) {
	pool := &sandboxv1alpha1.Pool{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pool", Namespace: "default"},
	}
	ctx := context.Background()

	evictLabel := map[string]string{eviction.LabelEvict: ""}
	normalLabel := map[string]string{"app": "test"}

	tests := []struct {
		name          string
		pods          []*corev1.Pod
		podAllocation map[string]string
		expectNames   []string
	}{
		{
			name: "no eviction labels keeps all pods",
			pods: []*corev1.Pod{
				newEvictionTestPod("pod-1", normalLabel, false),
				newEvictionTestPod("pod-2", normalLabel, false),
			},
			podAllocation: map[string]string{},
			expectNames:   []string{"pod-1", "pod-2"},
		},
		{
			name: "unallocated eviction-labeled pods are excluded",
			pods: []*corev1.Pod{
				newEvictionTestPod("pod-1", evictLabel, false),
				newEvictionTestPod("pod-2", normalLabel, false),
			},
			podAllocation: map[string]string{},
			expectNames:   []string{"pod-2"},
		},
		{
			name: "allocated eviction-labeled pods are kept",
			pods: []*corev1.Pod{
				newEvictionTestPod("pod-1", evictLabel, false),
				newEvictionTestPod("pod-2", normalLabel, false),
			},
			podAllocation: map[string]string{"pod-1": "sandbox-1"},
			expectNames:   []string{"pod-1", "pod-2"},
		},
		{
			name: "mix of allocated and unallocated eviction-labeled pods",
			pods: []*corev1.Pod{
				newEvictionTestPod("pod-1", evictLabel, false),
				newEvictionTestPod("pod-2", evictLabel, false),
				newEvictionTestPod("pod-3", normalLabel, false),
			},
			podAllocation: map[string]string{"pod-1": "sandbox-1"},
			expectNames:   []string{"pod-1", "pod-3"},
		},
		{
			name: "deleting pods with eviction label are not excluded (DeletionTimestamp skips NeedsEviction)",
			pods: []*corev1.Pod{
				newEvictionTestPod("pod-1", evictLabel, true),
			},
			podAllocation: map[string]string{},
			expectNames:   []string{"pod-1"},
		},
		{
			name:          "empty pod list",
			pods:          []*corev1.Pod{},
			podAllocation: map[string]string{},
			expectNames:   []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newEvictionTestReconciler()
			got := r.filterEvictingPods(ctx, pool, tt.pods, tt.podAllocation)

			if len(got) != len(tt.expectNames) {
				t.Fatalf("filterEvictingPods() returned %d pods, want %d", len(got), len(tt.expectNames))
			}
			for i, pod := range got {
				if pod.Name != tt.expectNames[i] {
					t.Errorf("pod[%d] = %s, want %s", i, pod.Name, tt.expectNames[i])
				}
			}
		})
	}
}

func TestHandlePodEvictions(t *testing.T) {
	pool := &sandboxv1alpha1.Pool{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pool", Namespace: "default"},
	}
	ctx := context.Background()

	evictLabel := map[string]string{eviction.LabelEvict: ""}
	normalLabel := map[string]string{"app": "test"}

	t.Run("evicts unallocated pods with eviction label", func(t *testing.T) {
		pod1 := newEvictionTestPod("pod-1", evictLabel, false)
		pod2 := newEvictionTestPod("pod-2", normalLabel, false)
		r := newEvictionTestReconciler(pod1, pod2)

		err := r.handlePodEvictions(ctx, pool, []*corev1.Pod{pod1, pod2}, map[string]string{})
		if err != nil {
			t.Fatalf("handlePodEvictions() returned error: %v", err)
		}

		// pod-1 should be deleted
		got := &corev1.Pod{}
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-1", Namespace: "default"}, got); err == nil {
			t.Error("expected pod-1 to be deleted")
		}
		// pod-2 should still exist
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-2", Namespace: "default"}, got); err != nil {
			t.Error("expected pod-2 to still exist")
		}
	})

	t.Run("skips allocated pods with eviction label", func(t *testing.T) {
		pod1 := newEvictionTestPod("pod-1", evictLabel, false)
		r := newEvictionTestReconciler(pod1)

		podAllocation := map[string]string{"pod-1": "sandbox-1"}
		err := r.handlePodEvictions(ctx, pool, []*corev1.Pod{pod1}, podAllocation)
		if err != nil {
			t.Fatalf("handlePodEvictions() returned error: %v", err)
		}

		// pod-1 should still exist
		got := &corev1.Pod{}
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-1", Namespace: "default"}, got); err != nil {
			t.Error("expected allocated pod-1 to still exist")
		}
	})

	t.Run("skips pods without eviction label", func(t *testing.T) {
		pod1 := newEvictionTestPod("pod-1", normalLabel, false)
		r := newEvictionTestReconciler(pod1)

		err := r.handlePodEvictions(ctx, pool, []*corev1.Pod{pod1}, map[string]string{})
		if err != nil {
			t.Fatalf("handlePodEvictions() returned error: %v", err)
		}

		got := &corev1.Pod{}
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-1", Namespace: "default"}, got); err != nil {
			t.Error("expected pod-1 to still exist")
		}
	})

	t.Run("skips pods already deleting", func(t *testing.T) {
		pod1 := newEvictionTestPod("pod-1", evictLabel, true)
		r := newEvictionTestReconciler(pod1)

		err := r.handlePodEvictions(ctx, pool, []*corev1.Pod{pod1}, map[string]string{})
		if err != nil {
			t.Fatalf("handlePodEvictions() returned error: %v", err)
		}

		got := &corev1.Pod{}
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-1", Namespace: "default"}, got); err != nil {
			t.Error("expected deleting pod-1 to still exist")
		}
	})

	t.Run("evicts multiple idle pods and keeps allocated ones", func(t *testing.T) {
		pod1 := newEvictionTestPod("pod-1", evictLabel, false)
		pod2 := newEvictionTestPod("pod-2", evictLabel, false)
		pod3 := newEvictionTestPod("pod-3", evictLabel, false)
		r := newEvictionTestReconciler(pod1, pod2, pod3)

		podAllocation := map[string]string{"pod-2": "sandbox-1"}
		err := r.handlePodEvictions(ctx, pool, []*corev1.Pod{pod1, pod2, pod3}, podAllocation)
		if err != nil {
			t.Fatalf("handlePodEvictions() returned error: %v", err)
		}

		got := &corev1.Pod{}
		// pod-1 (idle, eviction-labeled) -> deleted
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-1", Namespace: "default"}, got); err == nil {
			t.Error("expected pod-1 to be deleted")
		}
		// pod-2 (allocated, eviction-labeled) -> kept
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-2", Namespace: "default"}, got); err != nil {
			t.Error("expected allocated pod-2 to still exist")
		}
		// pod-3 (idle, eviction-labeled) -> deleted
		if err := r.Client.Get(ctx, types.NamespacedName{Name: "pod-3", Namespace: "default"}, got); err == nil {
			t.Error("expected pod-3 to be deleted")
		}
	})
}
