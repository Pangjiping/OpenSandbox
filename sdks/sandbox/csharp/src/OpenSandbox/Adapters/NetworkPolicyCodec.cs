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

using System.Text.Json;
using System.Linq;
using OpenSandbox.Core;
using OpenSandbox.Models;

namespace OpenSandbox.Adapters;

/// <summary>
/// Shared JSON mapping between <see cref="NetworkPolicy"/>/<see cref="NetworkRule"/>
/// and the egress policy wire format used by both the sandbox-side egress sidecar
/// and the lifecycle networkpolicy control-plane API.
/// </summary>
internal static class NetworkPolicyCodec
{
    public static NetworkPolicy ParsePolicy(JsonElement element)
    {
        var policy = new NetworkPolicy();

        if (element.TryGetProperty("defaultAction", out var defaultAction) &&
            defaultAction.ValueKind == JsonValueKind.String)
        {
            policy.DefaultAction = ParseNetworkRuleAction(defaultAction.GetString());
        }

        if (element.TryGetProperty("egress", out var egress) &&
            egress.ValueKind == JsonValueKind.Array)
        {
            policy.Egress = egress.EnumerateArray().Select(ParseNetworkRule).ToList();
        }

        return policy;
    }

    public static List<Dictionary<string, object?>> ToRulesPayload(IReadOnlyList<NetworkRule> rules)
    {
        return rules.Select(r =>
        {
            // Fail fast at the call site on a rule that neither names a
            // target nor scopes ports — the server would reject it with a
            // 422, but surfacing it here points at the exact rule.
            if (string.IsNullOrWhiteSpace(r.Target) && r.Ports is not { Count: > 0 })
            {
                throw new ArgumentException("NetworkRule requires target, ports, or both.", nameof(rules));
            }

            // target/ports are omitted (never null) when unset: a port-only
            // rule must reach the sidecar as {"action":"deny","ports":[25]}.
            var payload = new Dictionary<string, object?>
            {
                ["action"] = r.Action == NetworkRuleAction.Allow ? "allow" : "deny",
            };
            if (!string.IsNullOrWhiteSpace(r.Target))
            {
                payload["target"] = r.Target;
            }
            if (r.Ports is { Count: > 0 })
            {
                payload["ports"] = r.Ports;
            }
            return payload;
        }).ToList();
    }

    public static NetworkRule ParseNetworkRule(JsonElement element)
    {
        var actionText = element.GetProperty("action").GetString();

        // The sidecar marshals target without omitempty, so a port-only rule
        // arrives as "target": "" rather than an absent key — treat blank
        // the same as absent so reads stay symmetric with writes.
        string? target = null;
        if (element.TryGetProperty("target", out var targetElement) &&
            targetElement.ValueKind == JsonValueKind.String)
        {
            target = targetElement.GetString();
            if (string.IsNullOrWhiteSpace(target))
            {
                target = null;
            }
        }

        List<int>? ports = null;
        if (element.TryGetProperty("ports", out var portsElement) &&
            portsElement.ValueKind == JsonValueKind.Array)
        {
            ports = new List<int>();
            foreach (var portElement in portsElement.EnumerateArray())
            {
                if (portElement.ValueKind != JsonValueKind.Number || !portElement.TryGetInt32(out var port))
                {
                    throw new SandboxApiException(
                        $"Invalid port element in network rule: {portElement.GetRawText()}");
                }
                ports.Add(port);
            }
        }

        return new NetworkRule
        {
            Action = ParseNetworkRuleAction(actionText),
            Target = target,
            Ports = ports
        };
    }

    public static NetworkRuleAction ParseNetworkRuleAction(string? action)
    {
        return action?.ToLowerInvariant() switch
        {
            "allow" => NetworkRuleAction.Allow,
            "deny" => NetworkRuleAction.Deny,
            _ => throw new SandboxApiException($"Invalid network rule action: {action ?? "<null>"}")
        };
    }
}
