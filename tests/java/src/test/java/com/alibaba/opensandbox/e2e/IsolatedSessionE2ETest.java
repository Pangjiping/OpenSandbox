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

package com.alibaba.opensandbox.e2e;

import static org.junit.jupiter.api.Assertions.*;

import com.alibaba.opensandbox.sandbox.Sandbox;
import com.alibaba.opensandbox.sandbox.domain.models.execd.executions.Execution;
import com.alibaba.opensandbox.sandbox.domain.models.execd.isolated.CreateIsolatedSessionRequest;
import com.alibaba.opensandbox.sandbox.domain.models.execd.isolated.IsolatedCapabilities;
import com.alibaba.opensandbox.sandbox.domain.models.execd.isolated.IsolatedRunRequest;
import com.alibaba.opensandbox.sandbox.domain.models.execd.isolated.IsolatedWorkspaceSpec;
import com.alibaba.opensandbox.sandbox.domain.services.IsolationSession;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class IsolatedSessionE2ETest extends BaseE2ETest {

    private static final Logger log = LoggerFactory.getLogger(IsolatedSessionE2ETest.class);
    private Sandbox sandbox;

    private static String stdoutText(Execution exec) {
        return exec.getLogs().getStdout().stream()
                .map(m -> m.getText())
                .collect(Collectors.joining());
    }

    @BeforeAll
    void setup() {
        sandbox =
                Sandbox.builder()
                        .connectionConfig(sharedConnectionConfig)
                        .image(getSandboxImage())
                        .readyTimeout(Duration.ofMinutes(2))
                        .extensions(Map.of("bootstrap.execd.isolation", "enable"))
                        .build();

        IsolatedCapabilities caps = sandbox.isolation().capabilities();
        log.info(
                "Isolation capabilities: available={} isolator={} version={} message={}",
                caps.getAvailable(),
                caps.getIsolator(),
                caps.getVersion(),
                caps.getMessage());
        if (!caps.getAvailable()) {
            fail("Isolation NOT available: " + (caps.getMessage() != null ? caps.getMessage() : "unknown reason"));
        }
    }

    @AfterAll
    void tearDown() {
        if (sandbox != null) {
            sandbox.kill();
            sandbox.close();
        }
    }

    @Test
    @Order(1)
    void testCapabilities() {
        IsolatedCapabilities caps = sandbox.isolation().capabilities();
        assertTrue(caps.getAvailable());
    }

    @Test
    @Order(2)
    void testSessionLifecycle() {
        IsolationSession session =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/tmp", "rw"),
                                "balanced", null, null, null, null, null, null));
        assertNotNull(session.getSessionId());

        var state = session.get();
        assertEquals("active", state.getStatus());

        session.delete();
    }

    @Test
    @Order(3)
    void testRunEcho() {
        IsolationSession session =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/tmp", "rw"),
                                "balanced", null, null, null, null, null, null));
        try {
            Execution exec = session.run(new IsolatedRunRequest("echo hello-isolation", null, null));
            assertTrue(stdoutText(exec).contains("hello-isolation"));
        } finally {
            session.delete();
        }
    }

    @Test
    @Order(4)
    void testPidIsolation() {
        IsolationSession session =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/tmp", "rw"),
                                "balanced", null, null, null, null, null, null));
        try {
            Execution exec = session.run(new IsolatedRunRequest("echo $$", null, null));
            int pid = Integer.parseInt(stdoutText(exec).trim());
            assertTrue(pid <= 2, "expected PID 1 or 2, got " + pid);
        } finally {
            session.delete();
        }
    }

    @Test
    @Order(5)
    void testRunWithEnvs() {
        IsolationSession session =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/tmp", "rw"),
                                "balanced", null, null, null, null, null, null));
        try {
            Execution exec =
                    session.run(new IsolatedRunRequest(
                            "echo $MY_VAR",
                            Map.of("MY_VAR", "test-value-42"),
                            null));
            assertTrue(stdoutText(exec).contains("test-value-42"));
        } finally {
            session.delete();
        }
    }

    @Test
    @Order(6)
    void testSessionStatePersists() {
        IsolationSession session =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/tmp", "rw"),
                                "balanced", null, null, null, null, null, null));
        try {
            session.run(new IsolatedRunRequest("export PERSIST_VAR=abc123", null, null));
            Execution exec = session.run(new IsolatedRunRequest("echo $PERSIST_VAR", null, null));
            assertTrue(stdoutText(exec).contains("abc123"));
        } finally {
            session.delete();
        }
    }

    @Test
    @Order(7)
    void testTmpIsolation() {
        sandbox.commands().run("mkdir -p /workspace");

        IsolationSession sessionA =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/workspace", "rw"),
                                "strict", null, null, null, null, null, null));
        IsolationSession sessionB =
                sandbox.isolation()
                        .create(new CreateIsolatedSessionRequest(
                                new IsolatedWorkspaceSpec("/workspace", "rw"),
                                "strict", null, null, null, null, null, null));
        try {
            sessionA.run(new IsolatedRunRequest(
                    "echo secret > /tmp/isolated_test_file.txt", null, null));
            Execution exec = sessionB.run(new IsolatedRunRequest(
                    "cat /tmp/isolated_test_file.txt 2>&1 || echo NOT_FOUND", null, null));
            String text = stdoutText(exec);
            assertTrue(
                    text.contains("NOT_FOUND") || text.contains("No such file"),
                    "expected /tmp isolation, got: " + text);
        } finally {
            sessionA.delete();
            sessionB.delete();
        }
    }
}
