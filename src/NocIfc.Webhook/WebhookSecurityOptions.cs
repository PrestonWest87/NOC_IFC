using System.Globalization;

namespace NocIfc.Webhook;

public sealed record WebhookSecurityOptions(
    string HmacSecret,
    string SignatureHeader,
    string TimestampHeader,
    int ReplayWindowSeconds,
    int MaxBodyBytes,
    bool AllowUnsigned)
{
    public static WebhookSecurityOptions FromConfiguration(IConfiguration configuration) => new(
        configuration["WEBHOOK_HMAC_SECRET"] ?? "",
        configuration["WEBHOOK_SIGNATURE_HEADER"] ?? "X-SolarWinds-Signature",
        configuration["WEBHOOK_TIMESTAMP_HEADER"] ?? "X-SolarWinds-Timestamp",
        ReadInteger(configuration["WEBHOOK_REPLAY_WINDOW_SECONDS"], 300, "WEBHOOK_REPLAY_WINDOW_SECONDS", 0, 86_400),
        ReadInteger(configuration["WEBHOOK_MAX_BODY_BYTES"], 1_048_576, "WEBHOOK_MAX_BODY_BYTES", 1, 16 * 1024 * 1024),
        ReadBoolean(configuration["ALLOW_UNSIGNED_WEBHOOKS"], false));

    private static int ReadInteger(string? value, int fallback, string name, int minimum, int maximum) =>
        value is null
            ? fallback
            : int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
                && parsed >= minimum && parsed <= maximum
                ? parsed
                : throw new InvalidOperationException($"{name} must be between {minimum} and {maximum}.");

    private static bool ReadBoolean(string? value, bool fallback) => value is null
        ? fallback
        : bool.TryParse(value, out var parsed)
            ? parsed
            : throw new InvalidOperationException("ALLOW_UNSIGNED_WEBHOOKS must be true or false.");
}
