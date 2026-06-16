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

using OpenSandbox.Models;
using Xunit;
using Xunit.Abstractions;

namespace OpenSandbox.E2ETests;

[Collection("CSharp E2E Tests")]
public sealed class IsolatedSessionE2ETests : IAsyncLifetime
{
    private readonly E2ETestFixture _fixture;
    private readonly ITestOutputHelper _output;
    private Sandbox? _sandbox;

    public IsolatedSessionE2ETests(E2ETestFixture fixture, ITestOutputHelper output)
    {
        _fixture = fixture;
        _output = output;
    }

    private static string StdoutText(Execution exec)
        => string.Join("", exec.Logs.Stdout.Select(m => m.Text));

    public async Task InitializeAsync()
    {
        _sandbox = await Sandbox.CreateAsync(new SandboxCreateOptions
        {
            Image = _fixture.DefaultImage,
            ConnectionConfig = _fixture.ConnectionConfig,
            Extensions = new Dictionary<string, string>
            {
                ["bootstrap.execd.isolation"] = "enable"
            }
        });

        var caps = await _sandbox.Isolation.CapabilitiesAsync();
        _output.WriteLine(
            $"Isolation capabilities: available={caps.Available} isolator={caps.Isolator} " +
            $"version={caps.Version} message={caps.Message}");
        Assert.True(caps.Available, $"Isolation NOT available: {caps.Message ?? "unknown reason"}");
    }

    public async Task DisposeAsync()
    {
        if (_sandbox != null)
        {
            await _sandbox.KillAsync();
            await _sandbox.DisposeAsync();
        }
    }

    [Fact]
    public async Task TestCapabilities()
    {
        var caps = await _sandbox!.Isolation.CapabilitiesAsync();
        Assert.True(caps.Available);
    }

    [Fact]
    public async Task TestSessionLifecycle()
    {
        var session = await _sandbox!.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/tmp", "rw")));
        Assert.NotEmpty(session.SessionId);

        var state = await session.GetAsync();
        Assert.Equal("active", state.Status);

        await session.DeleteAsync();
    }

    [Fact]
    public async Task TestRunEcho()
    {
        var session = await _sandbox!.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/tmp", "rw")));
        try
        {
            var exec = await session.RunAsync("echo hello-isolation");
            Assert.Contains("hello-isolation", StdoutText(exec));
        }
        finally
        {
            await session.DeleteAsync();
        }
    }

    [Fact]
    public async Task TestPidIsolation()
    {
        var session = await _sandbox!.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/tmp", "rw")));
        try
        {
            var exec = await session.RunAsync("echo $$");
            var pid = int.Parse(StdoutText(exec).Trim());
            Assert.True(pid <= 2, $"expected PID 1 or 2, got {pid}");
        }
        finally
        {
            await session.DeleteAsync();
        }
    }

    [Fact]
    public async Task TestRunWithEnvs()
    {
        var session = await _sandbox!.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/tmp", "rw")));
        try
        {
            var exec = await session.RunAsync(
                "echo $MY_VAR",
                new IsolatedRunOpts(new Dictionary<string, string> { ["MY_VAR"] = "test-value-42" }));
            Assert.Contains("test-value-42", StdoutText(exec));
        }
        finally
        {
            await session.DeleteAsync();
        }
    }

    [Fact]
    public async Task TestSessionStatePersists()
    {
        var session = await _sandbox!.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/tmp", "rw")));
        try
        {
            await session.RunAsync("export PERSIST_VAR=abc123");
            var exec = await session.RunAsync("echo $PERSIST_VAR");
            Assert.Contains("abc123", StdoutText(exec));
        }
        finally
        {
            await session.DeleteAsync();
        }
    }

    [Fact]
    public async Task TestTmpIsolation()
    {
        await _sandbox!.Commands.RunAsync("mkdir -p /workspace");

        var sessionA = await _sandbox.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/workspace", "rw"), "strict"));
        var sessionB = await _sandbox.Isolation.CreateAsync(
            new CreateIsolatedSessionRequest(new IsolatedWorkspaceSpec("/workspace", "rw"), "strict"));
        try
        {
            await sessionA.RunAsync("echo secret > /tmp/isolated_test_file.txt");
            var exec = await sessionB.RunAsync(
                "cat /tmp/isolated_test_file.txt 2>&1 || echo NOT_FOUND");
            Assert.True(
                StdoutText(exec).Contains("NOT_FOUND") || StdoutText(exec).Contains("No such file"),
                $"expected /tmp isolation, got: {StdoutText(exec)}");
        }
        finally
        {
            await sessionA.DeleteAsync();
            await sessionB.DeleteAsync();
        }
    }
}
