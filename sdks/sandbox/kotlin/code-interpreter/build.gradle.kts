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

// See sandbox/build.gradle.kts for rationale. code-interpreter transitively depends on the
// shaded `jsonParser` from :sandbox at runtime, but at compile time still needs the original
// kotlinx-serialization types on the classpath. Keep it in compileOnly + shaded configuration
// so the published jar bundles the relocated copy and the pom omits the runtime dependency.
val shadedDependencies: Configuration by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    api(project(":sandbox"))
    implementation(project(":sandbox-api"))

    api(libs.kotlin.stdlib)
    api(libs.slf4j.api)

    implementation(libs.okhttp)
    implementation(libs.okhttp.logging)
    compileOnly(libs.bundles.serialization)
    shadedDependencies(libs.bundles.serialization)

    testImplementation(libs.bundles.testing)
    testImplementation(libs.bundles.serialization)
    testRuntimeOnly(libs.junit.platform.launcher)
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

tasks.withType<org.jetbrains.dokka.gradle.DokkaTask>().configureEach {
    dokkaSourceSets {
        named("main") {
            moduleName.set("CodeInterpreter")
        }
    }
}

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
