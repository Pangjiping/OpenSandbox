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

package com.alibaba.opensandbox.benchmark

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.time.Duration

/**
 * Client for the mock server's control endpoints:
 * `GET /__stats`, `POST /__config`, `POST /__reset`.
 */
class MockControl(
    baseUrl: String,
    requestTimeout: Duration,
) {
    private val client =
        OkHttpClient.Builder()
            .connectTimeout(requestTimeout)
            .readTimeout(requestTimeout)
            .build()
    private val base = baseUrl.trimEnd('/')

    private val json = Json { ignoreUnknownKeys = true }

    fun ping(): Boolean =
        try {
            client.newCall(Request.Builder().url("$base/__stats").get().build()).execute().use { it.isSuccessful }
        } catch (e: Exception) {
            false
        }

    fun stats(): Map<String, Any?> = get("__stats")

    fun reset() {
        post("__reset", buildJsonObject {})
    }

    fun setFaults(createFailureRate: Double? = null, execdFailureRate: Double? = null, poisonExisting: Boolean = false) {
        val body =
            buildJsonObject {
                createFailureRate?.let { put("createFailureRate", it) }
                execdFailureRate?.let { put("execdFailureRate", it) }
                if (poisonExisting) put("poisonExisting", true)
            }
        post("__config", body)
    }

    private fun get(path: String): Map<String, Any?> {
        val response = client.newCall(Request.Builder().url("$base/$path").get().build()).execute()
        response.use {
            if (!it.isSuccessful) {
                throw IllegalStateException("mock $path failed: HTTP ${it.code}")
            }
            val body = it.body?.string() ?: "{}"
            return json.parseToJsonElement(body).jsonObject
        }
    }

    private fun post(
        path: String,
        body: JsonObject,
    ) {
        val request =
            Request.Builder()
                .url("$base/$path")
                .post(body.toString().toRequestBody("application/json".toMediaType()))
                .build()
        client.newCall(request).execute().use {
            if (!it.isSuccessful) {
                throw IllegalStateException("mock $path failed: HTTP ${it.code} ${it.body?.string()}")
            }
        }
    }
}
