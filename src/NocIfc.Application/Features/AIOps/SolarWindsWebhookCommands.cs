using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Domain.AIOps;

namespace NocIfc.Application.Features.AIOps;

public static class SolarWindsWebhookNormalizer
{
    private static readonly string[] ResolutionWords = ["resolved", "up", "ok", "clear", "operational", "recovered"];
    private static readonly string[] FingerprintOrder = ["INTERNET", "COMMS_EQUIPMENT", "POWER_SUPPLIES", "COMPUTE", "SCADA"];
    private static readonly IReadOnlyDictionary<string, string[]> Fingerprints = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["INTERNET"] = ["vsat", "cellular", "sd-wan", "modem", "radio", "isp", "internet"],
        ["COMMS_EQUIPMENT"] = ["fw", "firewall", "asa", "palo", "fortigate", "meraki", "rtr", "router", "asr", "isr", "gateway", "sw", "switch", "nexus", "catalyst", "idf", "mdf", "ap", "wireless", "wlc"],
        ["POWER_SUPPLIES"] = ["ups", "pdu", "ats", "battery", "generator", "hvac", "ac unit", "dc power", "dc controller"],
        ["COMPUTE"] = ["vm", "host", "server", "storage", "san", "nas", "esxi"],
        ["SCADA"] = ["rtu", "plc", "meter", "substation", "plant", "relay", "sel-"],
    };
    private static readonly Regex Ipv4Pattern = new(@"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex ResolutionPattern = new(
        $@"\b(?:{string.Join("|", ResolutionWords.Select(Regex.Escape))})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static SolarWindsWebhookEvent Normalize(JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("SolarWinds payload must be a JSON object.");
        }
        var nodeDetails = GetObject(payload, "Node_Details");
        var custom = GetObject(payload, "Custom_Properties_Universal");
        var description = ReadText(payload, "description");
        var nodeName = FirstText(nodeDetails, "NodeName", "SysName")
            ?? ReadText(payload, "entity_caption") ?? "Unknown";
        var ipAddress = ReadText(nodeDetails, "IP_Address") ??
            Ipv4Pattern.Match(payload.GetRawText()).Value;
        if (ipAddress.Length == 0) ipAddress = "Unknown";
        var severity = ReadText(payload, "severity") ?? ReadText(custom, "Severity") ?? "Unknown";
        var alertLevel = ReadText(payload, "Alert_Level") ?? ReadText(custom, "Alert_Level") ?? "Unknown";
        var eventType = FirstText(payload, "AlertName", "check", "class", "description") ?? "Unknown";
        var status = ReadText(nodeDetails, "StatusDescription") ?? description ?? "Unknown";
        var isResolution = ResolutionPattern.IsMatch($"{status} {description}");
        if (isResolution) status = "Resolved";
        var deviceHint = FirstText(nodeDetails, "MachineType")
            ?? ReadText(custom, "Node_Type")
            ?? ReadText(payload, "entity_type")
            ?? "Unknown";
        var deviceType = ClassifyDevice($"{nodeName} {eventType} {deviceHint}", deviceHint);
        var site = FirstText(custom, "Site", "City") ?? "Unknown";
        return new SolarWindsWebhookEvent(
            Bound(nodeName, 512), Bound(ipAddress, 64), Bound(severity, 128), Bound(alertLevel, 128),
            Bound(eventType, 512), Bound(status, 512), isResolution, Bound(deviceType, 128), Bound(site, 255),
            Bound(description ?? "No description provided", 10_000));
    }

    public static JsonObject AddNormalizedAlertLevel(JsonElement payload, string alertLevel)
    {
        var result = JsonNode.Parse(payload.GetRawText()) as JsonObject
            ?? throw new ArgumentException("SolarWinds payload must be a JSON object.");
        result["Normalized_Alert_Level"] = alertLevel;
        return result;
    }

    private static string ClassifyDevice(string corpus, string hint)
    {
        var normalized = AiopsRcaAnalysisEngine.NormalizeDomainHint(hint);
        if (!string.IsNullOrEmpty(normalized)) return normalized;
        var lower = corpus.ToLowerInvariant();
        foreach (var domain in FingerprintOrder)
        {
            if (Fingerprints[domain].Any(keyword => lower.Contains(keyword, StringComparison.Ordinal))) return domain;
        }
        return "Network Node";
    }

    private static JsonElement GetObject(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out var item)
            && item.ValueKind == JsonValueKind.Object ? item : default;

    private static string? FirstText(JsonElement value, params string[] properties)
    {
        foreach (var property in properties)
        {
            var text = ReadText(value, property);
            if (!string.IsNullOrWhiteSpace(text)) return text;
        }
        return null;
    }

    private static string? ReadText(JsonElement value, string property)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(property, out var item)
            || item.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }
        return item.ValueKind switch
        {
            JsonValueKind.String => item.GetString(),
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            JsonValueKind.Number => item.GetRawText(),
            _ => null,
        };
    }

    private static string Bound(string value, int maximum) => value[..Math.Min(value.Length, maximum)];
}

public sealed class SolarWindsWebhookCommands(ISolarWindsWebhookStore store)
{
    public async Task ExecuteAsync(byte[] body, CancellationToken cancellationToken)
    {
        using var document = JsonDocument.Parse(body);
        if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.EnumerateObject().Any())
        {
            throw new ArgumentException("SolarWinds payload must be a non-empty JSON object.");
        }
        var normalized = SolarWindsWebhookNormalizer.Normalize(document.RootElement);
        var raw = SolarWindsWebhookNormalizer.AddNormalizedAlertLevel(document.RootElement, normalized.AlertLevel);
        await store.PersistAsync(normalized, raw.ToJsonString(), DateTime.UtcNow, cancellationToken);
    }
}
