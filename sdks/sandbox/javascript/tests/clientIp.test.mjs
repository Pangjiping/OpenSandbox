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

import assert from "node:assert/strict";
import test from "node:test";

import {
  probeOutboundIp,
  getClientIp,
  withClientIp,
  _setClientIpForTest,
  _resetClientIpCacheForTest,
} from "../dist/internal.js";

const HEADER = "OPEN-SANDBOX-CLIENT-IP";

function headersOf(result) {
  // Normalize to a Headers instance from either the returned init or Request input.
  if (result.input instanceof Request) return new Headers(result.input.headers);
  return new Headers(result.init?.headers);
}

test("withClientIp sets the header for a string input", (t) => {
  t.after(_resetClientIpCacheForTest);
  _setClientIpForTest("10.9.8.7");
  const out = withClientIp("http://x/y", { headers: { "X-Foo": "bar" } });
  const h = headersOf(out);
  assert.equal(h.get(HEADER), "10.9.8.7");
  assert.equal(h.get("X-Foo"), "bar"); // existing header preserved
});

test("withClientIp preserves headers already on a Request input", (t) => {
  t.after(_resetClientIpCacheForTest);
  _setClientIpForTest("10.9.8.7");
  const req = new Request("http://x/y", {
    method: "POST",
    headers: { "X-Demo-Label": "js", "OPEN-SANDBOX-API-KEY": "secret" },
  });
  const out = withClientIp(req, undefined);
  const h = headersOf(out);
  assert.equal(h.get(HEADER), "10.9.8.7");
  assert.equal(h.get("X-Demo-Label"), "js"); // must NOT be dropped
  assert.equal(h.get("OPEN-SANDBOX-API-KEY"), "secret"); // must NOT be dropped
  assert.ok(out.input instanceof Request);
  assert.equal(out.input.method, "POST"); // method preserved
});

test("withClientIp does not overwrite a user-provided value", (t) => {
  t.after(_resetClientIpCacheForTest);
  _setClientIpForTest("10.9.8.7");
  const out = withClientIp("http://x/y", {
    headers: { "open-sandbox-client-ip": "192.168.0.9" },
  });
  assert.equal(headersOf(out).get(HEADER), "192.168.0.9");
});

test("withClientIp is a no-op when the IP is unavailable", (t) => {
  t.after(_resetClientIpCacheForTest);
  _setClientIpForTest("");
  const out = withClientIp("http://x/y", { headers: { "X-Foo": "bar" } });
  assert.equal(headersOf(out).get(HEADER), null);
  assert.equal(headersOf(out).get("X-Foo"), "bar");
});

test("getClientIp returns the cached value", (t) => {
  t.after(_resetClientIpCacheForTest);
  _setClientIpForTest("172.16.5.4");
  assert.equal(getClientIp(), "172.16.5.4");
});

test("probeOutboundIp returns a valid IP or empty string", async (t) => {
  t.after(_resetClientIpCacheForTest);
  _resetClientIpCacheForTest();
  const ip = await probeOutboundIp();
  if (ip === "") {
    return; // best-effort: allowed in a network-less environment
  }
  // Octets constrained to 0-255 so an obviously invalid address would fail.
  const octet = "(25[0-5]|2[0-4]\\d|1?\\d?\\d)";
  assert.match(ip, new RegExp(`^${octet}(\\.${octet}){3}$`));
  assert.ok(!ip.startsWith("127."), `unexpected loopback IP: ${ip}`);
  assert.notEqual(ip, "0.0.0.0");
});
