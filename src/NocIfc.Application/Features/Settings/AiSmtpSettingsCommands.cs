using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Application.Features.Settings;

public sealed record AiSmtpSettings(
    string? LlmEndpoint,
    string LlmProvider,
    bool LlmApiKeyConfigured,
    string? LlmModelName,
    bool? IsActive,
    int? LlmContextWindow,
    string ActiveSmtpProvider,
    bool? SmtpEnabled,
    string? SmtpServer,
    int? SmtpPort,
    string? SmtpUsername,
    string? SmtpSender,
    string? SmtpRecipient,
    bool SmtpPasswordConfigured,
    bool GmailSmtpEnabled,
    string GmailSmtpUsername,
    string GmailSmtpSender,
    bool GmailSmtpClientIdConfigured,
    bool GmailSmtpClientSecretConfigured,
    bool GmailSmtpRefreshTokenConfigured);

public sealed record AiSmtpSettingsUpdate(
    string? LlmEndpoint,
    string? LlmApiKey,
    string? LlmModelName,
    string? LlmProvider,
    bool? IsActive,
    int? LlmContextWindow,
    string? ActiveSmtpProvider,
    bool? SmtpEnabled,
    string? SmtpServer,
    int? SmtpPort,
    string? SmtpUsername,
    string? SmtpPassword,
    string? SmtpSender,
    string? SmtpRecipient,
    string? GmailSmtpUsername,
    string? GmailSmtpClientId,
    string? GmailSmtpClientSecret,
    string? GmailSmtpRefreshToken,
    string? GmailSmtpSender,
    bool? GmailSmtpEnabled,
    IReadOnlySet<string> ProvidedFields);

public sealed class AiSmtpSettingsCommands(IAiSmtpSettingsStore settings, IEmailSender emailSender)
{
    private static readonly IReadOnlyDictionary<string, int> TextLimits = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["llm_endpoint"] = 2048,
        ["llm_api_key"] = 4096,
        ["llm_model_name"] = 256,
        ["smtp_server"] = 255,
        ["smtp_username"] = 254,
        ["smtp_password"] = 1024,
        ["smtp_sender"] = 254,
        ["smtp_recipient"] = 2000,
        ["gmail_smtp_username"] = 254,
        ["gmail_smtp_client_id"] = 255,
        ["gmail_smtp_client_secret"] = 1024,
        ["gmail_smtp_refresh_token"] = 4096,
        ["gmail_smtp_sender"] = 254,
    };

    private static readonly HashSet<string> BooleanFields =
    ["is_active", "smtp_enabled", "gmail_smtp_enabled"];

    public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) =>
        settings.GetAsync(cancellationToken);

    public async Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken)
    {
        var allowed = TextLimits.Keys.Concat(BooleanFields)
            .Concat(["llm_context_window", "smtp_port", "llm_provider", "active_smtp_provider"])
            .ToHashSet(StringComparer.Ordinal);
        if (update.ProvidedFields.Count == 0)
        {
            throw new ArgumentException("Provide at least one configuration setting.");
        }
        var unknown = update.ProvidedFields.FirstOrDefault(field => !allowed.Contains(field));
        if (unknown is not null)
        {
            throw new ArgumentException($"Unsupported configuration field: {unknown}.");
        }

        CheckLength(update.LlmEndpoint, "llm_endpoint", 2048);
        CheckLength(update.LlmApiKey, "llm_api_key", 4096);
        CheckLength(update.LlmModelName, "llm_model_name", 256);
        CheckLength(update.SmtpServer, "smtp_server", 255);
        CheckLength(update.SmtpUsername, "smtp_username", 254);
        CheckLength(update.SmtpPassword, "smtp_password", 1024);
        CheckLength(update.SmtpSender, "smtp_sender", 254);
        CheckLength(update.SmtpRecipient, "smtp_recipient", 2000);
        CheckLength(update.GmailSmtpUsername, "gmail_smtp_username", 254);
        CheckLength(update.GmailSmtpClientId, "gmail_smtp_client_id", 255);
        CheckLength(update.GmailSmtpClientSecret, "gmail_smtp_client_secret", 1024);
        CheckLength(update.GmailSmtpRefreshToken, "gmail_smtp_refresh_token", 4096);
        CheckLength(update.GmailSmtpSender, "gmail_smtp_sender", 254);

        var provider = update.LlmProvider;
        if (update.ProvidedFields.Contains("llm_provider"))
        {
            provider = string.IsNullOrWhiteSpace(provider) ? "openai_compatible" : provider.Trim().ToLowerInvariant();
            if (provider is not ("openai_compatible" or "ollama_openai" or "ollama_native" or "vllm"))
            {
                throw new ArgumentException($"Unsupported LLM provider: {provider}.");
            }
        }

        if (update.ProvidedFields.Contains("active_smtp_provider")
            && update.ActiveSmtpProvider is not ("smtp" or "gmail"))
        {
            throw new ArgumentException("active_smtp_provider must be either 'smtp' or 'gmail'.");
        }
        if (update.ProvidedFields.Contains("smtp_port") && update.SmtpPort is not (>= 1 and <= 65535))
        {
            throw new ArgumentException("smtp_port must be an integer between 1 and 65535.");
        }
        if (update.ProvidedFields.Contains("llm_context_window")
            && update.LlmContextWindow is { } contextWindow
            && contextWindow is < 4096 or > 1_000_000)
        {
            throw new ArgumentException("llm_context_window must be between 4096 and 1000000.");
        }
        foreach (var field in BooleanFields)
        {
            if (update.ProvidedFields.Contains(field) && GetBoolean(update, field) is null)
            {
                throw new ArgumentException($"{field} must be a boolean.");
            }
        }

        await settings.SaveAsync(update with { LlmProvider = provider }, cancellationToken);
    }

    public async Task<EmailSendResult> SendTestEmailAsync(string recipient, CancellationToken cancellationToken)
    {
        var address = (recipient ?? "").Trim();
        if (!EmailAddressRules.IsValid(address))
        {
            throw new ArgumentException("Enter one valid email address.");
        }
        return await emailSender.SendPlainTextAsync(
            address,
            "SMTP configuration test",
            "This message confirms that the active NOC IFC email sender can deliver mail.",
            cancellationToken);
    }

    private static bool? GetBoolean(AiSmtpSettingsUpdate update, string field) => field switch
    {
        "is_active" => update.IsActive,
        "smtp_enabled" => update.SmtpEnabled,
        "gmail_smtp_enabled" => update.GmailSmtpEnabled,
        _ => null,
    };

    private static void CheckLength(string? value, string field, int maximum)
    {
        if (value is not null && value.Length > maximum)
        {
            throw new ArgumentException($"{field} must be text no longer than {maximum} characters.");
        }
    }
}
