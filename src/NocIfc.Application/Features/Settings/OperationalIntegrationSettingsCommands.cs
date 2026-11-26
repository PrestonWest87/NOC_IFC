using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Application.Features.Settings;

public sealed record IntegrationEnvironmentSettings(
    string RiskAlertRecipients,
    string RemedyforceTicketEmail,
    string NocNotifyEmail,
    string NocOnpageEmail,
    string ItnetworkOnpageEmail,
    string ElasticUrl,
    string ElasticApiKey,
    bool ElasticVerifyCerts,
    string? ElasticCaCerts,
    double ElasticRequestTimeout,
    int ElasticMaxResults,
    string? CrimeAlertSms,
    string? CrimeAlertEmail);

public sealed record OperationalIntegrationSettings(
    string RiskAlertRecipients,
    string RemedyforceTicketEmail,
    string NocNotifyEmail,
    string NocOnpageEmail,
    string ItnetworkOnpageEmail,
    string ElasticUrl,
    bool ElasticApiKeyConfigured,
    bool ElasticVerifyCerts,
    string ElasticCaCerts,
    double ElasticRequestTimeout,
    int ElasticMaxResults,
    string CrimeAlertSms,
    string CrimeAlertEmail,
    IReadOnlyDictionary<string, string> Sources);

public sealed record OperationalIntegrationSettingsUpdate(
    string? RiskAlertRecipients,
    string? RemedyforceTicketEmail,
    string? NocNotifyEmail,
    string? NocOnpageEmail,
    string? ItnetworkOnpageEmail,
    string? ElasticUrl,
    string? ElasticApiKey,
    bool? ElasticVerifyCerts,
    string? ElasticCaCerts,
    double? ElasticRequestTimeout,
    int? ElasticMaxResults,
    string? CrimeAlertSms,
    string? CrimeAlertEmail,
    IReadOnlySet<string> ProvidedFields);

public sealed class OperationalIntegrationSettingsCommands(IOperationalIntegrationSettingsStore settings)
{
    private static readonly string[] TextLimits =
    [
        "risk_alert_recipients:5000", "remedyforce_ticket_email:2000", "noc_notify_email:2000",
        "noc_onpage_email:2000", "itnetwork_onpage_email:2000", "elastic_url:2048",
        "elastic_api_key:4096", "elastic_ca_certs:2048", "crime_alert_sms:2000", "crime_alert_email:2000",
    ];

    public Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken) =>
        settings.GetAsync(cancellationToken);

    public async Task SaveAsync(
        OperationalIntegrationSettingsUpdate update,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var allowed = TextLimits.Select(value => value[..value.IndexOf(':')])
            .Append("elastic_verify_certs")
            .Append("elastic_request_timeout")
            .Append("elastic_max_results")
            .ToHashSet(StringComparer.Ordinal);
        if (update.ProvidedFields.Count == 0)
        {
            throw new ArgumentException("Provide at least one integration setting.");
        }
        var unknown = update.ProvidedFields.Where(field => !allowed.Contains(field)).Order().FirstOrDefault();
        if (unknown is not null)
        {
            throw new ArgumentException($"Unsupported integration setting: {unknown}");
        }

        var normalized = update with
        {
            RiskAlertRecipients = NormalizeRecipients(update.RiskAlertRecipients, "risk_alert_recipients"),
            RemedyforceTicketEmail = NormalizeRecipients(update.RemedyforceTicketEmail, "remedyforce_ticket_email"),
            NocNotifyEmail = NormalizeRecipients(update.NocNotifyEmail, "noc_notify_email"),
            NocOnpageEmail = NormalizeRecipients(update.NocOnpageEmail, "noc_onpage_email"),
            ItnetworkOnpageEmail = NormalizeRecipients(update.ItnetworkOnpageEmail, "itnetwork_onpage_email"),
            CrimeAlertSms = NormalizeRecipients(update.CrimeAlertSms, "crime_alert_sms"),
            CrimeAlertEmail = NormalizeRecipients(update.CrimeAlertEmail, "crime_alert_email"),
            ElasticUrl = NormalizeElasticUrl(update.ElasticUrl),
            ElasticApiKey = TrimBounded(update.ElasticApiKey, "elastic_api_key", 4096),
            ElasticCaCerts = TrimBounded(update.ElasticCaCerts, "elastic_ca_certs", 2048),
        };
        CheckLength(normalized.RiskAlertRecipients, "risk_alert_recipients", 5000);
        CheckLength(normalized.RemedyforceTicketEmail, "remedyforce_ticket_email", 2000);
        CheckLength(normalized.NocNotifyEmail, "noc_notify_email", 2000);
        CheckLength(normalized.NocOnpageEmail, "noc_onpage_email", 2000);
        CheckLength(normalized.ItnetworkOnpageEmail, "itnetwork_onpage_email", 2000);
        CheckLength(normalized.ElasticUrl, "elastic_url", 2048);
        CheckLength(normalized.CrimeAlertSms, "crime_alert_sms", 2000);
        CheckLength(normalized.CrimeAlertEmail, "crime_alert_email", 2000);
        if (normalized.ElasticRequestTimeout is { } timeout && (!double.IsFinite(timeout) || timeout <= 0 || timeout > 120))
        {
            throw new ArgumentException("elastic_request_timeout must be greater than 0 and at most 120 seconds.");
        }
        if (normalized.ElasticMaxResults is < 1 or > 5000)
        {
            throw new ArgumentException("elastic_max_results must be an integer between 1 and 5000.");
        }

        await settings.SaveAsync(normalized, actorUserId, cancellationToken);
    }

    private static string? NormalizeRecipients(string? value, string field)
    {
        if (value is null)
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }

        var candidates = value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Select(candidate => candidate.Trim())
            .Where(candidate => candidate.Length > 0)
            .ToArray();
        if (candidates.Length > 100)
        {
            throw new ArgumentException("No more than 100 recipients may be configured per setting.");
        }

        var recipients = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var address in candidates)
        {
            if (!EmailAddressRules.IsValid(address))
            {
                throw new ArgumentException($"{field} must contain comma- or semicolon-separated email addresses.");
            }
            if (seen.Add(address))
            {
                recipients.Add(address);
            }
        }
        return string.Join(", ", recipients);
    }

    private static string? NormalizeElasticUrl(string? value)
    {
        if (value is null)
        {
            return null;
        }
        var url = value.Trim().TrimEnd('/');
        if (url.Length == 0)
        {
            return "";
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsed)
            || parsed.Scheme is not ("http" or "https")
            || string.IsNullOrEmpty(parsed.Host)
            || parsed.UserInfo.Length > 0
            || parsed.Query.Length > 0
            || parsed.Fragment.Length > 0)
        {
            throw new ArgumentException("elastic_url must be an HTTP(S) URL without credentials, query, or fragment.");
        }
        return url;
    }

    private static string? TrimBounded(string? value, string field, int maximum)
    {
        if (value is null)
        {
            return null;
        }
        var trimmed = value.Trim();
        CheckLength(trimmed, field, maximum);
        return trimmed;
    }

    private static void CheckLength(string? value, string field, int maximum)
    {
        if (value is not null && value.Length > maximum)
        {
            throw new ArgumentException($"{field} must be no longer than {maximum} characters.");
        }
    }
}
