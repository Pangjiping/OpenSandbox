#
# Copyright 2025 Alibaba Group Holding Ltd.
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
#
"""
Synchronous direct egress sidecar adapter implementation.
"""

import logging

import httpx

from opensandbox.adapters.converter.exception_converter import ExceptionConverter
from opensandbox.adapters.converter.response_handler import (
    handle_api_error,
    require_parsed,
)
from opensandbox.adapters.egress_http_log import format_egress_http_response
from opensandbox.config.connection_sync import ConnectionConfigSync
from opensandbox.models.sandboxes import NetworkPolicy, NetworkRule, SandboxEndpoint
from opensandbox.sync.services.egress import EgressSync

logger = logging.getLogger(__name__)


class EgressAdapterSync(EgressSync):
    """Blocking direct egress sidecar adapter using the generated egress client."""

    def __init__(self, connection_config: ConnectionConfigSync, endpoint: SandboxEndpoint) -> None:
        self.connection_config = connection_config
        self.endpoint = endpoint
        from opensandbox.api.egress import Client

        # Trailing "/" so relative OpenAPI paths (e.g. "policy") resolve under .../proxy/{port}/
        # per RFC 3986; without it, "policy" can incorrectly resolve to .../proxy/policy.
        base_url = f"{self.connection_config.protocol}://{self.endpoint.endpoint}".rstrip("/") + "/"
        timeout_seconds = self.connection_config.request_timeout.total_seconds()
        timeout = httpx.Timeout(timeout_seconds)
        headers = {
            "User-Agent": self.connection_config.user_agent,
            **self.connection_config.headers,
            **self.endpoint.headers,
        }

        self._client = Client(
            base_url=base_url,
            timeout=timeout,
        )
        self._httpx_client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
            transport=self.connection_config.transport,
        )
        self._client.set_httpx_client(self._httpx_client)
        # Do not use URL.join("/policy"): a leading "/" replaces the entire path (→ http://host/policy).
        self._policy_url = base_url.rstrip("/") + "/policy"

    def get_policy(self) -> NetworkPolicy:
        response_obj = None
        try:
            from opensandbox.api.egress.api.policy import get_policy
            from opensandbox.api.egress.models.network_policy import (
                NetworkPolicy as ApiNetworkPolicy,
            )
            from opensandbox.api.egress.models.policy_status_response import (
                PolicyStatusResponse,
            )
            from opensandbox.api.egress.types import Unset

            response_obj = get_policy.sync_detailed(client=self._client)
            logger.info(
                "Egress GET policy: request_url=%s %s",
                self._policy_url,
                format_egress_http_response(response_obj),
            )
            handle_api_error(response_obj, "Get egress policy")
            parsed = require_parsed(response_obj, PolicyStatusResponse, "Get egress policy")
            policy = parsed.policy
            if isinstance(policy, Unset):
                raise ValueError("Egress policy response missing policy payload")
            if not isinstance(policy, ApiNetworkPolicy):
                raise TypeError(f"Expected NetworkPolicy, got {type(policy).__name__}")
            return NetworkPolicy.model_validate(policy.to_dict())
        except Exception as e:
            if response_obj is not None:
                logger.error(
                    "Egress GET policy failed: request_url=%s %s",
                    self._policy_url,
                    format_egress_http_response(response_obj),
                    exc_info=True,
                )
            else:
                logger.error(
                    "Egress GET policy failed: request_url=%s (no HTTP response received) error=%s",
                    self._policy_url,
                    e,
                    exc_info=True,
                )
            raise ExceptionConverter.to_sandbox_exception(e) from e

    def patch_rules(self, rules: list[NetworkRule]) -> None:
        response_obj = None
        try:
            from opensandbox.api.egress.api.policy import patch_policy
            from opensandbox.api.egress.models.network_rule import (
                NetworkRule as ApiNetworkRule,
            )
            from opensandbox.api.egress.models.network_rule_action import (
                NetworkRuleAction,
            )

            response_obj = patch_policy.sync_detailed(
                client=self._client,
                body=[
                    ApiNetworkRule(
                        action=NetworkRuleAction(rule.action),
                        target=rule.target,
                    )
                    for rule in rules
                ],
            )
            logger.info(
                "Egress PATCH policy: request_url=%s rules_count=%s %s",
                self._policy_url,
                len(rules),
                format_egress_http_response(response_obj),
            )
            handle_api_error(response_obj, "Patch egress rules")
        except Exception as e:
            if response_obj is not None:
                logger.error(
                    "Egress PATCH policy failed: request_url=%s rules_count=%s %s",
                    self._policy_url,
                    len(rules),
                    format_egress_http_response(response_obj),
                    exc_info=True,
                )
            else:
                logger.error(
                    "Egress PATCH policy failed: request_url=%s rules_count=%s "
                    "(no HTTP response received) error=%s",
                    self._policy_url,
                    len(rules),
                    e,
                    exc_info=True,
                )
            raise ExceptionConverter.to_sandbox_exception(e) from e
