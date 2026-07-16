/*
 * Copyright 2025 Alibaba Group Holding Ltd.
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

plugins {
    `java-platform`
}

dependencies {
    constraints {
        api(project(":sandbox"))
        api(project(":sandbox-api"))
        api(project(":sandbox-pool-redis"))
        api(project(":code-interpreter"))

        api(libs.kotlin.stdlib)
        api(libs.okhttp)
        api(libs.okhttp.logging)
        api(libs.slf4j.api)
        // kotlinx-serialization is not constrained here on purpose: it is shaded into the SDK
        // jars (com.alibaba.opensandbox.shaded.kotlinx.serialization.*) and no longer appears
        // in the SDK's runtime classpath. Downstream users who want to use kotlinx-serialization
        // directly should pick a version themselves; the SDK does not care.
    }
}
