using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Contracts;

public sealed class AiSmtpSettingsUpdateRequest
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Values { get; init; } = new(StringComparer.Ordinal);

    public AiSmtpSettingsUpdate ToUpdate()
    {
        var allowed = new HashSet<string>(
            [
                "llm_endpoint", "llm_api_key", "llm_model_name", "llm_provider", "is_active",
                "llm_context_window", "active_smtp_provider", "smtp_enabled", "smtp_server",
                "smtp_port", "smtp_username", "smtp_password", "smtp_sender", "smtp_recipient",
                "gmail_smtp_username", "gmail_smtp_client_id", "gmail_smtp_client_secret",
                "gmail_smtp_refresh_token", "gmail_smtp_sender", "gmail_smtp_enabled",
            ],
            StringComparer.Ordinal);
        var unknown = Values.Keys.FirstOrDefault(field => !allowed.Contains(field));
        if (unknown is not null)
        {
            throw new ArgumentException($"Unsupported configuration field: {unknown}.");
        }

        return new AiSmtpSettingsUpdate(
            ReadString("llm_endpoint"),
            ReadString("llm_api_key"),
            ReadString("llm_model_name"),
            ReadString("llm_provider"),
            ReadBoolean("is_active"),
            ReadInteger("llm_context_window"),
            ReadString("active_smtp_provider"),
            ReadBoolean("smtp_enabled"),
            ReadString("smtp_server"),
            ReadInteger("smtp_port"),
            ReadString("smtp_username"),
            ReadString("smtp_password"),
            ReadString("smtp_sender"),
            ReadString("smtp_recipient"),
            ReadString("gmail_smtp_username"),
            ReadString("gmail_smtp_client_id"),
            ReadString("gmail_smtp_client_secret"),
            ReadString("gmail_smtp_refresh_token"),
            ReadString("gmail_smtp_sender"),
            ReadBoolean("gmail_smtp_enabled"),
            Values.Keys.ToHashSet(StringComparer.Ordinal));
    }

    private string? ReadString(string field)
    {
        if (!Values.TryGetValue(field, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException($"{field} must be text or null.");
        }
        return value.GetString();
    }

    private bool? ReadBoolean(string field)
    {
        if (!Values.TryGetValue(field, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new ArgumentException($"{field} must be a boolean.");
        }
        return value.GetBoolean();
    }

    private int? ReadInteger(string field)
    {
        if (!Values.TryGetValue(field, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw new ArgumentException($"{field} must be an integer.");
        }
        return number;
    }
}

public sealed record AiSmtpSettingsResponse(
    [property: JsonPropertyName("llm_endpoint")] string? LlmEndpoint,
    [property: JsonPropertyName("llm_provider")] string LlmProvider,
    [property: JsonPropertyName("llm_api_key_configured")] bool LlmApiKeyConfigured,
    [property: JsonPropertyName("llm_model_name")] string? LlmModelName,
    [property: JsonPropertyName("is_active")] bool? IsActive,
    [property: JsonPropertyName("llm_context_window")] int? LlmContextWindow,
    [property: JsonPropertyName("active_smtp_provider")] string ActiveSmtpProvider,
    [property: JsonPropertyName("smtp_enabled")] bool? SmtpEnabled,
    [property: JsonPropertyName("smtp_server")] string? SmtpServer,
    [property: JsonPropertyName("smtp_port")] int? SmtpPort,
    [property: JsonPropertyName("smtp_username")] string? SmtpUsername,
    [property: JsonPropertyName("smtp_sender")] string? SmtpSender,
    [property: JsonPropertyName("smtp_recipient")] string? SmtpRecipient,
    [property: JsonPropertyName("smtp_password_configured")] bool SmtpPasswordConfigured,
    [property: JsonPropertyName("gmail_smtp_enabled")] bool GmailSmtpEnabled,
    [property: JsonPropertyName("gmail_smtp_username")] string GmailSmtpUsername,
    [property: JsonPropertyName("gmail_smtp_sender")] string GmailSmtpSender,
    [property: JsonPropertyName("gmail_smtp_client_id_configured")] bool GmailSmtpClientIdConfigured,
    [property: JsonPropertyName("gmail_smtp_client_secret_configured")] bool GmailSmtpClientSecretConfigured,
    [property: JsonPropertyName("gmail_smtp_refresh_token_configured")] bool GmailSmtpRefreshTokenConfigured)
{
    public static AiSmtpSettingsResponse From(AiSmtpSettings settings) => new(
        settings.LlmEndpoint,
        settings.LlmProvider,
        settings.LlmApiKeyConfigured,
        settings.LlmModelName,
        settings.IsActive,
        settings.LlmContextWindow,
        settings.ActiveSmtpProvider,
        settings.SmtpEnabled,
        settings.SmtpServer,
        settings.SmtpPort,
        settings.SmtpUsername,
        settings.SmtpSender,
        settings.SmtpRecipient,
        settings.SmtpPasswordConfigured,
        settings.GmailSmtpEnabled,
        settings.GmailSmtpUsername,
        settings.GmailSmtpSender,
        settings.GmailSmtpClientIdConfigured,
        settings.GmailSmtpClientSecretConfigured,
        settings.GmailSmtpRefreshTokenConfigured);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class TestEmailRequest
{
    [JsonPropertyName("recipient")]
    public string? Recipient { get; init; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class LlmConnectionTestRequest
{
    [JsonPropertyName("llm_provider")]
    public string? Provider { get; init; } = "openai_compatible";

    [JsonPropertyName("llm_endpoint")]
    public string? Endpoint { get; init; } = "";

    [JsonPropertyName("llm_api_key")]
    public string? ApiKey { get; init; } = "";

    [JsonPropertyName("llm_model_name")]
    public string? ModelName { get; init; } = "gpt-4o-mini";

    public LlmConnectionTestInput ToInput() => new(Provider, Endpoint, ApiKey, ModelName);
}
