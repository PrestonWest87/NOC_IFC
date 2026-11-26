using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Contracts;

public sealed class IntegrationSettingsUpdateRequest
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Values { get; init; } = new(StringComparer.Ordinal);

    public OperationalIntegrationSettingsUpdate ToUpdate()
    {
        var allowed = new HashSet<string>(
            [
                "risk_alert_recipients", "remedyforce_ticket_email", "noc_notify_email",
                "noc_onpage_email", "itnetwork_onpage_email", "elastic_url", "elastic_api_key",
                "elastic_verify_certs", "elastic_ca_certs", "elastic_request_timeout",
                "elastic_max_results", "crime_alert_sms", "crime_alert_email",
            ],
            StringComparer.Ordinal);
        var unknown = Values.Keys.FirstOrDefault(key => !allowed.Contains(key));
        if (unknown is not null)
        {
            throw new ArgumentException($"Unsupported integration setting: {unknown}");
        }

        return new OperationalIntegrationSettingsUpdate(
            ReadString("risk_alert_recipients"),
            ReadString("remedyforce_ticket_email"),
            ReadString("noc_notify_email"),
            ReadString("noc_onpage_email"),
            ReadString("itnetwork_onpage_email"),
            ReadString("elastic_url"),
            ReadString("elastic_api_key"),
            ReadBool("elastic_verify_certs"),
            ReadString("elastic_ca_certs"),
            ReadDouble("elastic_request_timeout"),
            ReadInt("elastic_max_results"),
            ReadString("crime_alert_sms"),
            ReadString("crime_alert_email"),
            Values.Keys.ToHashSet(StringComparer.Ordinal));
    }

    private string? ReadString(string key)
    {
        if (!Values.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException($"{key} must be text or null.");
        }
        return value.GetString();
    }

    private bool? ReadBool(string key)
    {
        if (!Values.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new ArgumentException($"{key} must be a boolean or null.");
        }
        return value.GetBoolean();
    }

    private double? ReadDouble(string key)
    {
        if (!Values.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetDouble(out var number))
        {
            throw new ArgumentException($"{key} must be a number or null.");
        }
        return number;
    }

    private int? ReadInt(string key)
    {
        if (!Values.TryGetValue(key, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw new ArgumentException($"{key} must be an integer or null.");
        }
        return number;
    }
}

public sealed record IntegrationSettingsResponse(
    [property: JsonPropertyName("risk_alert_recipients")] string RiskAlertRecipients,
    [property: JsonPropertyName("remedyforce_ticket_email")] string RemedyforceTicketEmail,
    [property: JsonPropertyName("noc_notify_email")] string NocNotifyEmail,
    [property: JsonPropertyName("noc_onpage_email")] string NocOnpageEmail,
    [property: JsonPropertyName("itnetwork_onpage_email")] string ItnetworkOnpageEmail,
    [property: JsonPropertyName("elastic_url")] string ElasticUrl,
    [property: JsonPropertyName("elastic_api_key_configured")] bool ElasticApiKeyConfigured,
    [property: JsonPropertyName("elastic_verify_certs")] bool ElasticVerifyCerts,
    [property: JsonPropertyName("elastic_ca_certs")] string ElasticCaCerts,
    [property: JsonPropertyName("elastic_request_timeout")] double ElasticRequestTimeout,
    [property: JsonPropertyName("elastic_max_results")] int ElasticMaxResults,
    [property: JsonPropertyName("crime_alert_sms")] string CrimeAlertSms,
    [property: JsonPropertyName("crime_alert_email")] string CrimeAlertEmail,
    [property: JsonPropertyName("sources")] IReadOnlyDictionary<string, string> Sources)
{
    public static IntegrationSettingsResponse From(OperationalIntegrationSettings settings) => new(
        settings.RiskAlertRecipients,
        settings.RemedyforceTicketEmail,
        settings.NocNotifyEmail,
        settings.NocOnpageEmail,
        settings.ItnetworkOnpageEmail,
        settings.ElasticUrl,
        settings.ElasticApiKeyConfigured,
        settings.ElasticVerifyCerts,
        settings.ElasticCaCerts,
        settings.ElasticRequestTimeout,
        settings.ElasticMaxResults,
        settings.CrimeAlertSms,
        settings.CrimeAlertEmail,
        settings.Sources);
}
