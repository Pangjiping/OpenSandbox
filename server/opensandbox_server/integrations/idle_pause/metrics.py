# Copyright 2026 The OpenSandbox Authors
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

"""``opensandbox.server.idlep.*`` instruments (OSEP-0010 alignment).

Instruments are resolved lazily on first use so the sweeper never depends on
OTEL setup ordering; with ``[otel] enabled = false`` the global provider is a
noop meter and recording is a cheap no-op. Never raises.
"""

from __future__ import annotations

import logging
from typing import Optional

from opentelemetry import metrics

logger = logging.getLogger(__name__)

PAUSE_REQUESTS_COUNTER = "opensandbox.server.idlep.pause.requests"
PAUSE_LATENCY_HISTOGRAM = "opensandbox.server.idlep.pause.latency"

_meter: Optional[metrics.Meter] = None
_pause_requests = None
_pause_latency = None


def _instruments():
    global _meter, _pause_requests, _pause_latency
    if _pause_requests is None or _pause_latency is None:
        try:
            meter = _meter or metrics.get_meter("opensandbox.server")
            _meter = meter
            _pause_requests = meter.create_counter(
                name=PAUSE_REQUESTS_COUNTER,
                unit="{pause}",
                description="Idle-pause attempts by outcome (accepted / gated / failed).",
            )
            _pause_latency = meter.create_histogram(
                name=PAUSE_LATENCY_HISTOGRAM,
                unit="s",
                description="PauseSandbox accepted -> observed Paused.",
            )
        except Exception:  # pragma: no cover - defensive; never break a sweep
            logger.exception("Failed to create idlep instruments")
            return None, None
    return _pause_requests, _pause_latency


def record_pause_request(*, outcome: str) -> None:
    """Count one sweeper pause attempt. ``outcome``: accepted/gated/failed."""
    counter, _ = _instruments()
    if counter is None:
        return
    try:
        counter.add(1, attributes={"outcome": outcome})
    except Exception:
        logger.exception("Failed to record idlep.pause.requests")


def record_pause_latency(seconds: float) -> None:
    """Record one accepted -> Paused latency sample."""
    _, histogram = _instruments()
    if histogram is None:
        return
    try:
        histogram.record(seconds)
    except Exception:
        logger.exception("Failed to record idlep.pause.latency")
