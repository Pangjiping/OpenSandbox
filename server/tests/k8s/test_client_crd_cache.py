# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CRD-discovery cache of K8sClient.custom_resource_exists."""

from unittest.mock import MagicMock, patch

from kubernetes.client import V1APIResource, V1APIResourceList

from opensandbox_server.config import KubernetesRuntimeConfig
from opensandbox_server.services.k8s.client import K8sClient


def _client_with_discovery(resources):
    with patch.object(K8sClient, "_load_config"):
        k8s = K8sClient(KubernetesRuntimeConfig(informer_enabled=False))
    api = MagicMock()
    api.get_api_resources.return_value = V1APIResourceList(
        group_version="sandbox.fast.io/v1alpha2",
        resources=resources,
    )
    k8s._custom_objects_api = api
    return k8s, api


def test_custom_resource_exists_caches_discovery_round_trip():
    k8s, api = _client_with_discovery(
        [
            V1APIResource(
                name="sandboxes",
                singular_name="sandbox",
                kind="Sandbox",
                namespaced=True,
                verbs=["get", "list", "watch"],
            )
        ]
    )

    assert k8s.custom_resource_exists("sandbox.fast.io", "v1alpha2", "sandboxes") is True
    assert k8s.custom_resource_exists("sandbox.fast.io", "v1alpha2", "sandboxes") is True
    assert api.get_api_resources.call_count == 1, "repeated lists must hit the cache"


def test_custom_resource_exists_false_is_cached_too():
    k8s, api = _client_with_discovery(
        [
            V1APIResource(
                name="sandboxpools",
                singular_name="sandboxpool",
                kind="SandboxPool",
                namespaced=True,
                verbs=["get", "list", "watch"],
            )
        ]
    )

    assert k8s.custom_resource_exists("sandbox.fast.io", "v1alpha2", "sandboxes") is False
    assert k8s.custom_resource_exists("sandbox.fast.io", "v1alpha2", "sandboxes") is False
    assert api.get_api_resources.call_count == 1
