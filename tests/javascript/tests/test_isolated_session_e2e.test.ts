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

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Sandbox } from "@alibaba-group/opensandbox";
import type { OutputMessage } from "@alibaba-group/opensandbox";
import { createConnectionConfig, getSandboxImage } from "./base_e2e.js";

describe("IsolatedSession E2E", () => {
  let sandbox: Sandbox;

  beforeAll(async () => {
    sandbox = await Sandbox.create({
      image: getSandboxImage(),
      connectionConfig: createConnectionConfig(),
      extensions: { "bootstrap.execd.isolation": "enable" },
    });

    const caps = await sandbox.isolation.capabilities();
    console.log(
      `Isolation capabilities: available=${caps.available} isolator=${caps.isolator} version=${caps.version} message=${caps.message}`
    );
    if (!caps.available) {
      throw new Error(`Isolation NOT available: ${caps.message ?? "unknown reason"}`);
    }
  }, 120_000);

  afterAll(async () => {
    if (sandbox) {
      await sandbox.kill();
      await sandbox.close();
    }
  });

  it("test_capabilities", async () => {
    const caps = await sandbox.isolation.capabilities();
    expect(caps.available).toBe(true);
  });

  it("test_session_lifecycle", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    expect(session.sessionId).toBeTruthy();

    const state = await session.get();
    expect(state.status).toBe("active");

    await session.delete();
  });

  it("test_run_echo", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      const exec = await session.run("echo hello-isolation");
      expect(exec.logs.stdout.map(m => m.text).join("")).toContain("hello-isolation");
    } finally {
      await session.delete();
    }
  });

  it("test_pid_isolation", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      const exec = await session.run("echo $$");
      const pid = parseInt(exec.logs.stdout.map(m => m.text).join("").trim(), 10);
      expect(pid).toBeLessThanOrEqual(2);
    } finally {
      await session.delete();
    }
  });

  it("test_run_with_envs", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      const exec = await session.run(
        "echo $MY_VAR",
        { envs: { MY_VAR: "test-value-42" } }
      );
      expect(exec.logs.stdout.map(m => m.text).join("")).toContain("test-value-42");
    } finally {
      await session.delete();
    }
  });

  it("test_session_state_persists", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      await session.run("export PERSIST_VAR=abc123");
      const exec = await session.run("echo $PERSIST_VAR");
      expect(exec.logs.stdout.map(m => m.text).join("")).toContain("abc123");
    } finally {
      await session.delete();
    }
  });

  it("test_tmp_isolation", async () => {
    await sandbox.commands.run("mkdir -p /workspace");

    const sessionA = await sandbox.isolation.create({
      workspace: { path: "/workspace", mode: "rw" },
      profile: "strict",
    });
    const sessionB = await sandbox.isolation.create({
      workspace: { path: "/workspace", mode: "rw" },
      profile: "strict",
    });
    try {
      await sessionA.run("echo secret > /tmp/isolated_test_file.txt");
      const exec = await sessionB.run(
        "cat /tmp/isolated_test_file.txt 2>&1 || echo NOT_FOUND"
      );
      expect(
        exec.logs.stdout.map(m => m.text).join("").includes("NOT_FOUND") || exec.logs.stdout.map(m => m.text).join("").includes("No such file")
      ).toBe(true);
    } finally {
      await sessionA.delete();
      await sessionB.delete();
    }
  });

  it("test_run_with_handlers", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      const collected: string[] = [];
      await session.run(
        "echo handler-test",
        undefined,
        {
          onStdout: (msg: OutputMessage) => {
            collected.push(msg.text);
          },
        }
      );
      expect(collected.join("")).toContain("handler-test");
    } finally {
      await session.delete();
    }
  });

  it("test_files_via_run", async () => {
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "rw" },
    });
    try {
      await session.run("echo hello-from-sdk > /tmp/hello.txt");
      const exec = await session.run("cat /tmp/hello.txt");
      expect(exec.logs.stdout.map(m => m.text).join("")).toContain("hello-from-sdk");
    } finally {
      await session.delete();
    }
  });

  it("test_overlay_mode", async () => {
    const marker = "overlay_marker_file.txt";
    const session = await sandbox.isolation.create({
      workspace: { path: "/tmp", mode: "overlay" },
    });
    try {
      await session.run(`echo overlay-data > /tmp/${marker}`);
      const hostCheck = await sandbox.commands.run(
        `cat /tmp/${marker} 2>&1 || echo NOT_FOUND`
      );
      expect(
        hostCheck.logs.stdout.map(m => m.text).join("").includes("NOT_FOUND") || hostCheck.logs.stdout.map(m => m.text).join("").includes("No such file")
      ).toBe(true);
    } finally {
      await session.delete();
    }
  });
});
