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

"""Shared helpers for logging egress HTTP responses in adapters."""

_MAX_EGRESS_LOG_BODY = 2048


def format_egress_http_response(response_obj: object) -> str:
    """Short HTTP status + body preview for logs (egress policy responses are small JSON)."""
    status = getattr(response_obj, "status_code", None)
    content = getattr(response_obj, "content", b"") or b""
    try:
        status_int = int(status) if status is not None else -1
    except (TypeError, ValueError):
        status_int = -1
    if len(content) > _MAX_EGRESS_LOG_BODY:
        text = (
            content[:_MAX_EGRESS_LOG_BODY].decode("utf-8", errors="replace")
            + f"... [{len(content)} bytes total]"
        )
    else:
        text = content.decode("utf-8", errors="replace")
    return f"status={status_int} body={text!r}"
