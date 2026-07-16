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

import org.openapitools.generator.gradle.plugin.tasks.GenerateTask

plugins {
    alias(libs.plugins.openapi.generator)
    alias(libs.plugins.shadow)
}

repositories {
    mavenCentral()
}

// See sandbox/build.gradle.kts for rationale: kotlinx-serialization is used only for wire
// encoding, and the generated `$$serializer` classes reference kotlinx internals. Shade the
// runtime into com.alibaba.opensandbox.shaded.kotlinx.serialization so downstream consumers
// stay isolated from whatever kotlinx-serialization their classpath resolves to.
val shadedDependencies: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    implementation(libs.okhttp)
    compileOnly(libs.bundles.serialization)
    shadedDependencies(libs.bundles.serialization)
}

// shadowJar produces the module's primary artifact: this module's own classes plus a
// relocated copy of kotlinx-serialization. Both Maven and Gradle consumers pull the same
// shaded jar via the standard `com.alibaba.opensandbox:sandbox-api:<version>` coordinate.
tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
    // Empty classifier so this jar takes over the default `<module>-<version>.jar` name.
    archiveClassifier.set("")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE
    configurations = listOf(shadedDependencies)
    relocate("kotlinx.serialization", "com.alibaba.opensandbox.shaded.kotlinx.serialization")
    mergeServiceFiles()
    exclude("META-INF/versions/9/module-info.class")
    exclude("META-INF/maven/**")
}

// The plain `jar` task still runs (it's referenced by intra-project compilation and by
// the `apiElements`/`runtimeElements` variant metadata), but we redirect its output path
// via a classifier so it never collides with shadowJar's output on disk. The classifier
// output is *not* attached to the maven publication (see afterEvaluate below).
tasks.named<Jar>("jar") {
    archiveClassifier.set("plain")
}

tasks.named("assemble") { dependsOn(tasks.named("shadowJar")) }

// Swap in shadowJar as the maven publication's main artifact so downstream Maven consumers
// receive the shaded jar. The plain `jar` output (classifier=plain) is used for intra-project
// compile/test only and is stripped from the publication here.
afterEvaluate {
    extensions.configure<PublishingExtension> {
        publications.withType<MavenPublication>().configureEach {
            val shadowTask = tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar")
            // Drop both the auto-added main jar (classifier=null-turned-plain) and the plain
            // classifier artifact; keep sources / javadoc classifiers.
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

// Gradle-native (`.module`) consumers would resolve the plain jar via variant metadata,
// bypassing the swap above. Disable GMM so Gradle consumers fall back to the maven pom
// (which points at shadowJar). This is fine because our audience is Maven-based; the SDK
// is not published to consumers who need Gradle-specific variant selection.
tasks.withType<GenerateModuleMetadata>().configureEach {
    enabled = false
}

fun GenerateTask.configureCommonOptions() {
    outputs.doNotCacheIf("OpenAPI generation must reflect the current spec files") { true }

    generatorName.set("kotlin")
    library.set("jvm-okhttp4")

    typeMappings.set(
        mapOf(
            "object" to "kotlinx.serialization.json.JsonElement",
            "Object" to "kotlinx.serialization.json.JsonElement",
            "java.lang.Object" to "kotlinx.serialization.json.JsonElement",
            "Any" to "kotlinx.serialization.json.JsonElement",
            "kotlin.Any" to "kotlinx.serialization.json.JsonElement",
            "binary" to "java.io.InputStream",
            "file" to "java.io.InputStream",
        ),
    )

    importMappings.set(
        mapOf(
            "JsonElement" to "kotlinx.serialization.json.JsonElement",
        ),
    )

    configOptions.set(
        mapOf(
            "jvm8" to "true",
            "coroutine" to "false",
            "dateLibrary" to "java8",
            "serializationLibrary" to "kotlinx_serialization",
            "documentationProvider" to "kdoc",
            "useKtor" to "false",
            "omitGradleWrapper" to "true",
        ),
    )

    globalProperties.set(
        mapOf(
            "apiTests" to "false",
            "modelTests" to "false",
        ),
    )
}

val generateSandboxLifecycleApi =
    tasks.register<GenerateTask>("generateSandboxLifecycleApi") {
        configureCommonOptions()

        inputSpec.set(
            rootProject.projectDir.parentFile.parentFile.parentFile
                .resolve("specs/sandbox-lifecycle.yml").absolutePath,
        )
        outputDir.set(layout.buildDirectory.dir("generated/api/lifecycle").get().asFile.absolutePath)
        packageName.set("com.alibaba.opensandbox.sandbox.api")
        apiPackage.set("com.alibaba.opensandbox.sandbox.api")
        modelPackage.set("com.alibaba.opensandbox.sandbox.api.models")
    }

val generateExecdApi =
    tasks.register<GenerateTask>("generateExecdApi") {
        configureCommonOptions()

        inputSpec.set(rootProject.projectDir.parentFile.parentFile.parentFile.resolve("specs/execd-api.yaml").absolutePath)
        outputDir.set(layout.buildDirectory.dir("generated/api/execd").get().asFile.absolutePath)
        packageName.set("com.alibaba.opensandbox.sandbox.api.execd")
        apiPackage.set("com.alibaba.opensandbox.sandbox.api.execd")
        modelPackage.set("com.alibaba.opensandbox.sandbox.api.models.execd")
    }

val generateEgressApi =
    tasks.register<GenerateTask>("generateEgressApi") {
        configureCommonOptions()

        inputSpec.set(rootProject.projectDir.parentFile.parentFile.parentFile.resolve("specs/egress-api.yaml").absolutePath)
        outputDir.set(layout.buildDirectory.dir("generated/api/egress").get().asFile.absolutePath)
        packageName.set("com.alibaba.opensandbox.sandbox.api.egress")
        apiPackage.set("com.alibaba.opensandbox.sandbox.api.egress")
        modelPackage.set("com.alibaba.opensandbox.sandbox.api.models.egress")
    }

val generateDiagnosticApi =
    tasks.register<GenerateTask>("generateDiagnosticApi") {
        configureCommonOptions()

        inputSpec.set(rootProject.projectDir.parentFile.parentFile.parentFile.resolve("specs/diagnostic-api.yml").absolutePath)
        outputDir.set(layout.buildDirectory.dir("generated/api/diagnostic").get().asFile.absolutePath)
        packageName.set("com.alibaba.opensandbox.sandbox.api.diagnostic")
        apiPackage.set("com.alibaba.opensandbox.sandbox.api.diagnostic")
        modelPackage.set("com.alibaba.opensandbox.sandbox.api.models.diagnostic")
    }

val lifecycleSrc = generateSandboxLifecycleApi.map { file(it.outputDir).resolve("src/main/kotlin") }
val execdSrc = generateExecdApi.map { file(it.outputDir).resolve("src/main/kotlin") }
val egressSrc = generateEgressApi.map { file(it.outputDir).resolve("src/main/kotlin") }
val diagnosticSrc = generateDiagnosticApi.map { file(it.outputDir).resolve("src/main/kotlin") }
sourceSets {
    main {
        java.srcDirs(lifecycleSrc, execdSrc, egressSrc, diagnosticSrc)
    }
}
