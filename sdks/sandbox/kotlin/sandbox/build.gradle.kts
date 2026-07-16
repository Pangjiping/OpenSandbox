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
    alias(libs.plugins.shadow)
}

// Isolated configuration that carries only the kotlinx-serialization artifacts we want to
// relocate and bundle into the published jar. Kept separate from `implementation` so the
// generated pom does not declare kotlinx-serialization as a runtime dependency; downstream
// consumers whose classpath resolves an older kotlinx-serialization no longer clash with the
// shaded copy we ship inside the jar.
val shadedDependencies: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    implementation(project(":sandbox-api"))
    api(libs.kotlin.stdlib)
    api(libs.slf4j.api)

    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)

    // kotlinx-serialization is used only for internal wire encoding/decoding; hide it from
    // downstream classpath by shading + relocating into com.alibaba.opensandbox.shaded.
    compileOnly(libs.bundles.serialization)
    shadedDependencies(libs.bundles.serialization)

    testImplementation(libs.bundles.testing)
    testImplementation(libs.bundles.serialization)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Relocate kotlinx.serialization -> com.alibaba.opensandbox.shaded.kotlinx.serialization.
// The generated `$$serializer` classes reference internal kotlinx types; Shadow rewrites those
// references in the module's own bytecode as it repackages the shaded classes into the jar.
// See sandbox-api/build.gradle.kts for the rationale.
tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    archiveClassifier.set("")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    configurations = listOf(shadedDependencies)
    relocate("kotlinx.serialization", "com.alibaba.opensandbox.shaded.kotlinx.serialization")
    mergeServiceFiles()
    exclude("META-INF/versions/9/module-info.class")
    exclude("META-INF/maven/**")
}

tasks.named<Jar>("jar") {
    archiveClassifier.set("plain")
}

tasks.named("assemble") { dependsOn(tasks.named("shadowJar")) }

afterEvaluate {
    extensions.configure<PublishingExtension> {
        publications.withType<MavenPublication>().configureEach {
            val shadowTask = tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar")
            setArtifacts(
                artifacts.filter {
                    val c = it.classifier
                    !c.isNullOrEmpty() && c != "plain"
                },
            )
            artifact(shadowTask.map { it.archiveFile }) {
                classifier = ""
                extension = "jar"
                builtBy(shadowTask)
            }
        }
    }
}

tasks.withType<GenerateModuleMetadata>().configureEach {
    enabled = false
}

// Configure test tasks to use JDK 17
tasks.withType<Test> {
    javaLauncher.set(
        javaToolchains.launcherFor {
            languageVersion.set(JavaLanguageVersion.of(17))
        },
    )
    useJUnitPlatform()
}

// Configure test compilation to use JDK 17
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    if (name.contains("test", ignoreCase = true)) {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }
    compilerOptions {
        javaParameters.set(true)
    }
}

tasks.withType<JavaCompile> {
    if (name.contains("test", ignoreCase = true)) {
        javaCompiler.set(
            javaToolchains.compilerFor {
                languageVersion.set(JavaLanguageVersion.of(17))
            },
        )
    }
}
