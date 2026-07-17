/*
 * Copyright 2026 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.opensandbox.sandbox

import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Best-effort detection of the SDK host's own outbound IP address.
 *
 * Mirrors the well-known idiom of "dialing" a UDP socket to a fixed external
 * address and reading the local address the OS bound. UDP is connectionless, so
 * no packet is sent; the OS merely selects the outbound interface for the
 * default route. A literal IP avoids any DNS lookup.
 *
 * The detected IP is sent to the server via [CLIENT_IP_HEADER]. A custom
 * (non-standard) header name is used on purpose: standard forwarded headers such
 * as X-Forwarded-For are rewritten or stripped by intermediaries.
 */
internal object ClientIpDetector {
    const val CLIENT_IP_HEADER = "OPEN-SANDBOX-CLIENT-IP"

    private const val PROBE_HOST = "8.8.8.8"
    private const val PROBE_PORT = 80

    /** Detection function; overridable for tests. */
    @Volatile
    internal var detector: () -> String = ::detectOutboundIp

    @Volatile
    private var cached: String? = null

    /** Return the outbound IP, detected once and cached for the process. */
    @Synchronized
    fun clientIp(): String {
        cached?.let { return it }
        val value = detector()
        cached = value
        return value
    }

    /** Detect the outbound IP, or "" if it cannot be determined. */
    fun detectOutboundIp(): String {
        return try {
            DatagramSocket().use { socket ->
                socket.connect(InetAddress.getByName(PROBE_HOST), PROBE_PORT)
                val addr = socket.localAddress
                if (addr == null || addr.isAnyLocalAddress || addr.isLoopbackAddress) {
                    ""
                } else {
                    addr.hostAddress ?: ""
                }
            }
        } catch (_: Exception) {
            ""
        }
    }

    /** Reset detection state. Intended for tests only. */
    @Synchronized
    internal fun resetForTest() {
        cached = null
        detector = ::detectOutboundIp
    }
}
