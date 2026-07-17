// Copyright 2026 Alibaba Group Holding Ltd.
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

import { CLIENT_IP_HEADER } from "../core/constants.js";

// Detect the SDK host's own outbound IP using the same underlying logic as the
// other OpenSandbox SDKs: "dial" a UDP socket to a fixed external address and
// read the local address the OS bound. UDP is connectionless, so no packet is
// sent; the OS merely selects the outbound interface for the default route.
//
// Node's dgram connect is asynchronous, so detection runs once at module load
// and the result is cached. The header is added per request by the transport
// wrapper (see applyClientIpToInit), which reads the cached value; by the time
// any request is issued, detection has resolved. A custom (non-standard) header
// name is used on purpose: standard forwarded headers such as X-Forwarded-For
// are rewritten or stripped by intermediaries.

// Probe target. A literal IP (not a hostname) avoids any DNS lookup.
const PROBE_HOST = "8.8.8.8";
const PROBE_PORT = 80;

let cachedIp = "";
let detectionStarted = false;

function isNodeRuntime(): boolean {
  const p = (globalThis as any)?.process;
  return !!p?.versions?.node;
}

function isUsableIp(ip: unknown): ip is string {
  if (typeof ip !== "string" || ip.length === 0) return false;
  if (ip === "0.0.0.0" || ip === "::") return false;
  if (ip.startsWith("127.") || ip === "::1") return false;
  return true;
}

/**
 * Probe the local outbound IP via a UDP dial. Resolves to the IP or "" when it
 * cannot be determined. Best-effort: never rejects.
 */
export async function probeOutboundIp(): Promise<string> {
  if (!isNodeRuntime()) return "";
  try {
    // Dynamic, non-literal specifier keeps this Node-only and avoids requiring
    // `@types/node` or bundling `node:dgram` into browser builds.
    const specifier = "node:dgram";
    const dgram: any = await import(specifier);
    return await new Promise<string>((resolve) => {
      let settled = false;
      const socket = dgram.createSocket("udp4");
      const finish = (ip: string) => {
        if (settled) return;
        settled = true;
        try {
          socket.close();
        } catch {
          // ignore
        }
        resolve(isUsableIp(ip) ? ip : "");
      };
      socket.once("error", () => finish(""));
      try {
        socket.connect(PROBE_PORT, PROBE_HOST, () => {
          try {
            finish(socket.address()?.address ?? "");
          } catch {
            finish("");
          }
        });
      } catch {
        finish("");
      }
    });
  } catch {
    return "";
  }
}

function ensureDetectionStarted(): void {
  if (detectionStarted || !isNodeRuntime()) return;
  detectionStarted = true;
  void probeOutboundIp()
    .then((ip) => {
      cachedIp = ip;
    })
    .catch(() => {
      // best-effort
    });
}

// Kick off detection eagerly at import time so the result is ready by the time
// the first request is issued.
ensureDetectionStarted();

/** Return the detected outbound IP, or "" if not (yet) available. */
export function getClientIp(): string {
  return cachedIp;
}

/**
 * Add the client IP header to an outgoing request without dropping any headers
 * already set on the `input` (which may be a {@link Request}) or `init`.
 *
 * Returns the possibly-adjusted `{ input, init }`. The header is not added when
 * the IP is unavailable or a value is already present (case-insensitive), so a
 * caller-supplied value is never overridden.
 */
export function withClientIp(
  input: RequestInfo | URL,
  init?: RequestInit
): { input: RequestInfo | URL; init?: RequestInit } {
  const ip = getClientIp();
  if (!ip) return { input, init };

  const inputIsRequest = typeof Request !== "undefined" && input instanceof Request;

  // Merge headers from the Request input (if any) with init headers so nothing
  // is lost. init headers win on conflict, matching fetch(Request, init).
  const headers = new Headers(inputIsRequest ? (input as Request).headers : undefined);
  if (init?.headers) {
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  }

  if (headers.has(CLIENT_IP_HEADER)) return { input, init };
  headers.set(CLIENT_IP_HEADER, ip);

  if (inputIsRequest) {
    // Clone the Request preserving method/body/etc., with the merged headers.
    return { input: new Request(input as Request, { headers }), init };
  }
  return { input, init: { ...(init ?? {}), headers } };
}

/** Set the cached IP directly. Intended for tests only. */
export function _setClientIpForTest(ip: string): void {
  cachedIp = ip;
  detectionStarted = true;
}

/** Reset detection state so it re-probes on next import cycle. Tests only. */
export function _resetClientIpCacheForTest(): void {
  cachedIp = "";
  detectionStarted = false;
}
