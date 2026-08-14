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

plugins {
    kotlin("jvm") version "2.2.21"
    application
}

group = "com.alibaba.opensandbox"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

repositories {
    mavenLocal()
    exclusiveContent {
        forRepository {
            mavenLocal()
        }
        filter {
            includeGroup("com.alibaba.opensandbox")
        }
    }
    mavenCentral()
}

configurations.configureEach {
    resolutionStrategy.cacheDynamicVersionsFor(0, "seconds")
    resolutionStrategy.cacheChangingModulesFor(0, "seconds")
}

dependencies {
    // OpenSandbox Kotlin SDK (published to mavenLocal; see tests/benchmark/README.md).
    // The version is taken from the SDK's own gradle.properties so run.sh and
    // this module cannot drift; pass -PsandboxVersion=... to override.
    val sandboxVersion = (project.findProperty("sandboxVersion") as String?) ?: "1.0.18"
    implementation("com.alibaba.opensandbox:sandbox:$sandboxVersion")

    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.9.0")
    implementation("org.slf4j:slf4j-simple:2.0.9")
}

application {
    mainClass.set("com.alibaba.opensandbox.benchmark.MainKt")
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "11"
    targetCompatibility = "11"
}

