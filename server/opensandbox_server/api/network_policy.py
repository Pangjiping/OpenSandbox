# Copyright 2026 Alibaba Group Holding Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

"""Read/replace policy intent without exposing the Fastlet's loopback handler."""

import asyncio

from fastapi import APIRouter, HTTPException, Request

from opensandbox_server.api import lifecycle
from opensandbox_server.api.proxy import _proxy_http_request
from opensandbox_server.api.schema import NetworkPolicy
from opensandbox_server.services.composite_service import CompositeSandboxService
from opensandbox_server.services.fleets import FleetSandboxService

router = APIRouter(tags=["Sandboxes"])


def _fleets_service():
    service = lifecycle.sandbox_service
    if not isinstance(service, (FleetSandboxService, CompositeSandboxService)):
        raise HTTPException(404, detail="Fleets sandbox not found.")
    return service


@router.get("/sandboxes/{sandbox_id}/networkpolicy")
async def get_network_policy(request: Request, sandbox_id: str):
    if sandbox_id.startswith("flt-"):
        return await asyncio.to_thread(_fleets_service().get_network_policy, sandbox_id)
    return await _proxy_http_request(request, sandbox_id, 18080, "policy")


@router.put("/sandboxes/{sandbox_id}/networkpolicy")
async def replace_network_policy(request: Request, sandbox_id: str, policy: NetworkPolicy):
    if sandbox_id.startswith("flt-"):
        return await asyncio.to_thread(_fleets_service().replace_network_policy, sandbox_id, policy)
    return await _proxy_http_request(request, sandbox_id, 18080, "policy")
