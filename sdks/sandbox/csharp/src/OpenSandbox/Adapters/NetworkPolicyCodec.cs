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
        var payload = new List<Dictionary<string, object?>>(rules.Count);
        for (var i = 0; i < rules.Count; i++)
        {
            payload.Add(ToRulesPayloadEntry(rules[i], i));
        }
        return payload;
    }

    private static Dictionary<string, object?> ToRulesPayloadEntry(NetworkRule r, int index)
    {
        // Fail fast at the call site on a rule the server would 422, pointing
        // at the exact entry: a rule must name a target or scope ports, and
        // ports mirror the server-side constraints (1-65535, at most 256 per
        // rule, no duplicates).
        var hasTarget = !string.IsNullOrWhiteSpace(r.Target);
        var hasPorts = r.Ports is { Count: > 0 };
        if (!hasTarget && !hasPorts)
        {
            throw new ArgumentException($"NetworkRule[{index}] requires target, ports, or both.");
        }
        if (hasPorts)
        {
            var seen = new HashSet<int>();
            foreach (var port in r.Ports!)
            {
                if (port < 1 || port > 65535)
                {
                    throw new ArgumentException($"NetworkRule[{index}] port {port} out of range 1-65535.");
                }
                if (!seen.Add(port))
                {
                    throw new ArgumentException($"NetworkRule[{index}] has duplicate port {port}.");
                }
            }
            if (r.Ports.Count > 256)
            {
                throw new ArgumentException($"NetworkRule[{index}] has {r.Ports.Count} ports; at most 256 per rule.");
            }
        }

        // target/ports are omitted (never null) when unset: a port-only rule
        // must reach the sidecar as {"action":"deny","ports":[25]}. A blank
        // target is omitted too — the server normalizes it to "omitted", so
        // the rule degrades to a port-only rule exactly as it would there.
        var entry = new Dictionary<string, object?>
        {
            ["action"] = r.Action == NetworkRuleAction.Allow ? "allow" : "deny",
        };
        if (hasTarget)
        {
            entry["target"] = r.Target;
        }
        if (hasPorts)
        {
            entry["ports"] = r.Ports;
        }
        return entry;
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
        if (element.TryGetProperty("ports", out var portsElement))
        {
            if (portsElement.ValueKind == JsonValueKind.Array)
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

                if (ports.Count == 0)
                {
                    // The contract declares minItems: 1; accepting an empty
                    // list here would let a GET→PATCH round-trip turn the
                    // rule into "no ports" and trip the write-side checks.
                    throw new SandboxApiException("Invalid network rule: ports must not be empty");
                }
            }
            else if (portsElement.ValueKind != JsonValueKind.Null)
            {
                throw new SandboxApiException(
                    $"Invalid ports in network rule: {portsElement.GetRawText()}");
            }
            // Null ports means "not port-scoped": parsed as absent so a
            // read-back re-PATCHes without a ports key.
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
