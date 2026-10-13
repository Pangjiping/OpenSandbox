// Copyright 2026 The OpenSandbox Authors
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

using System.Net;
using System.Text;
using OpenSandbox.Adapters;
using OpenSandbox.Core;
using OpenSandbox.Internal;
using OpenSandbox.Models;
using Xunit;

namespace OpenSandbox.Tests;

/// <summary>
/// Port-scoped egress rule coverage for the codec: the sidecar marshals
/// target without omitempty, so a port-only rule always arrives as
/// "target": "" (never an absent key), and PATCH payloads must omit unset
/// fields rather than sending nulls.
/// </summary>
public class EgressAdapterNetworkPolicyTests
{
    private const string OkPolicyWithPortOnlyRule = """
        {
          "status": "ok",
          "policy": {
            "defaultAction": "deny",
            "egress": [
              { "action": "deny", "target": "", "ports": [25] }
            ]
          }
        }
        """;

    private const string OkPolicyWithTargetAndPorts = """
        {
          "status": "ok",
          "policy": {
            "defaultAction": "deny",
            "egress": [
              { "action": "allow", "target": "10.0.0.5", "ports": [22, 80] }
            ]
          }
        }
        """;

    private const string OkPolicyWithBoundaryPorts = """
        {
          "status": "ok",
          "policy": {
            "defaultAction": "deny",
            "egress": [
              { "action": "allow", "ports": [1, 65535] },
              { "action": "deny", "ports": [] }
            ]
          }
        }
        """;

    private const string OkPolicyWithMalformedPort = """
        {
          "status": "ok",
          "policy": {
            "defaultAction": "deny",
            "egress": [
              { "action": "allow", "ports": ["https"] }
            ]
          }
        }
        """;

    private const string OkResponse = """{ "status": "ok" }""";

    [Fact]
    public async Task GetPolicyAsync_ParsesPortOnlyRule_WithSidecarWireShape()
    {
        var (adapter, handler) = CreateAdapter(OkPolicyWithPortOnlyRule);

        var policy = await adapter.GetPolicyAsync();

        var rule = Assert.Single(policy.Egress!);
        Assert.Null(rule.Target);
        Assert.Equal(new List<int> { 25 }, rule.Ports);
    }

    [Fact]
    public async Task GetPolicyAsync_ParsesTargetWithPortsRule()
    {
        var (adapter, handler) = CreateAdapter(OkPolicyWithTargetAndPorts);

        var policy = await adapter.GetPolicyAsync();

        var rule = Assert.Single(policy.Egress!);
        Assert.Equal("10.0.0.5", rule.Target);
        Assert.Equal(new List<int> { 22, 80 }, rule.Ports);
    }

    [Fact]
    public async Task GetPolicyAsync_ParsesBoundaryPorts_AndEmptyList()
    {
        var (adapter, handler) = CreateAdapter(OkPolicyWithBoundaryPorts);

        var policy = await adapter.GetPolicyAsync();

        Assert.Equal(new List<int> { 1, 65535 }, policy.Egress![0].Ports);
        Assert.Empty(policy.Egress[1].Ports!);
    }

    [Fact]
    public async Task GetPolicyAsync_MalformedPortElement_ThrowsSandboxApiException()
    {
        var (adapter, handler) = CreateAdapter(OkPolicyWithMalformedPort);

        var ex = await Assert.ThrowsAsync<SandboxApiException>(() => adapter.GetPolicyAsync());
        Assert.Contains("Invalid port element", ex.Message);
    }

    [Fact]
    public async Task PatchRulesAsync_OmitsTargetKey_ForPortOnlyRule()
    {
        var (adapter, handler) = CreateAdapter(OkResponse);

        await adapter.PatchRulesAsync(new[] { new NetworkRule { Action = NetworkRuleAction.Deny, Ports = new List<int> { 25 } } });

        var body = Assert.Single(handler.Bodies);
        Assert.DoesNotContain("\"target\"", body);
        Assert.Contains("\"ports\":[25]", body);
    }

    [Fact]
    public async Task PatchRulesAsync_BlankTargetWithPorts_IsPortOnly()
    {
        var (adapter, handler) = CreateAdapter(OkResponse);

        await adapter.PatchRulesAsync(new[]
        {
            new NetworkRule { Action = NetworkRuleAction.Allow, Target = "  ", Ports = new List<int> { 22 } },
        });

        var body = Assert.Single(handler.Bodies);
        Assert.DoesNotContain("\"target\"", body);
        Assert.Contains("\"ports\":[22]", body);
    }

    [Fact]
    public async Task PatchRulesAsync_PlainTargetRule_Unchanged()
    {
        var (adapter, handler) = CreateAdapter(OkResponse);

        await adapter.PatchRulesAsync(new[] { new NetworkRule { Action = NetworkRuleAction.Allow, Target = "example.com" } });

        var body = Assert.Single(handler.Bodies);
        Assert.Contains("\"target\":\"example.com\"", body);
        Assert.DoesNotContain("\"ports\"", body);
    }

    [Fact]
    public async Task PatchRulesAsync_TargetWithPorts_SendsBoth()
    {
        var (adapter, handler) = CreateAdapter(OkResponse);

        await adapter.PatchRulesAsync(new[]
        {
            new NetworkRule { Action = NetworkRuleAction.Allow, Target = "10.0.0.5", Ports = new List<int> { 22, 80 } },
        });

        var body = Assert.Single(handler.Bodies);
        Assert.Contains("\"target\":\"10.0.0.5\"", body);
        Assert.Contains("\"ports\":[22,80]", body);
    }

    [Fact]
    public async Task PatchRulesAsync_NeitherTargetNorPorts_FailsFast()
    {
        var (adapter, handler) = CreateAdapter(OkResponse);

        var ex = await Assert.ThrowsAsync<ArgumentException>(
            () => adapter.PatchRulesAsync(new[] { new NetworkRule { Action = NetworkRuleAction.Allow } }));
        Assert.Contains("requires target, ports, or both", ex.Message);
    }

    private static (EgressAdapter Adapter, CaptureHandler Handler) CreateAdapter(string responseBody)
    {
        var handler = new CaptureHandler(responseBody);
        var wrapper = new HttpClientWrapper(
            new HttpClient(handler),
            "http://egress.local",
            new Dictionary<string, string>());
        return (new EgressAdapter(wrapper), handler);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;

        public CaptureHandler(string responseBody)
        {
            _responseBody = responseBody;
        }

        public List<string> Bodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Content != null)
            {
                Bodies.Add(await request.Content.ReadAsStringAsync().ConfigureAwait(false));
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_responseBody, Encoding.UTF8, "application/json"),
            };
        }
    }
}
