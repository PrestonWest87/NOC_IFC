using System.Globalization;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Settings;

public sealed record GlobalApplicationSettings(
    string PublicAppUrl,
    string TechStack,
    string MonitoredAsns,
    bool FailedLoginAlertEnabled,
    string FailedLoginAlertRecipients,
    int FailedLoginAlertThreshold,
    int FailedLoginAlertWindowMinutes);

public sealed record GlobalApplicationSettingsUpdate(
    string? PublicAppUrl,
    string? TechStack,
    string? MonitoredAsns,
    bool? FailedLoginAlertEnabled,
    string? FailedLoginAlertRecipients,
    int? FailedLoginAlertThreshold,
    int? FailedLoginAlertWindowMinutes);

public sealed class ApplicationSettingsCommands(IApplicationSettingsStore settings)
{
    public async Task<GlobalApplicationSettings?> GetAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var current = await settings.GetAsync(cancellationToken);
        if (current is null
            || user.IsAdministrator
            || user.AllowedActions.Contains("Action: Manage Application Settings", StringComparer.Ordinal))
        {
            return current;
        }
        return current with { FailedLoginAlertRecipients = "" };
    }

    public async Task SaveAsync(GlobalApplicationSettingsUpdate update, CancellationToken cancellationToken)
    {
        if (update.PublicAppUrl is null
            && update.TechStack is null
            && update.MonitoredAsns is null
            && update.FailedLoginAlertEnabled is null
            && update.FailedLoginAlertRecipients is null
            && update.FailedLoginAlertThreshold is null
            && update.FailedLoginAlertWindowMinutes is null)
        {
            throw new ArgumentException("Provide at least one application setting.");
        }
        if ((update.PublicAppUrl?.Length ?? 0) > 500
            || (update.TechStack?.Length ?? 0) > 1000
            || (update.MonitoredAsns?.Length ?? 0) > 1000
            || (update.FailedLoginAlertRecipients?.Length ?? 0) > 5000)
        {
            throw new ArgumentException("Application setting exceeds its maximum length.");
        }
        if (update.FailedLoginAlertThreshold is < 2 or > 100)
        {
            throw new ArgumentException("failed_login_alert_threshold must be an integer between 2 and 100.");
        }
        if (update.FailedLoginAlertWindowMinutes is < 1 or > 60)
        {
            throw new ArgumentException("failed_login_alert_window_minutes must be an integer between 1 and 60.");
        }

        var publicUrl = update.PublicAppUrl;
        if (publicUrl is not null)
        {
            publicUrl = publicUrl.Trim().TrimEnd('/');
            if (!Uri.TryCreate(publicUrl, UriKind.Absolute, out var parsed)
                || parsed.Scheme is not ("http" or "https")
                || string.IsNullOrEmpty(parsed.Host)
                || parsed.Query.Length > 0
                || parsed.Fragment.Length > 0)
            {
                throw new ArgumentException("public_app_url must be an HTTP(S) URL without a query or fragment.");
            }
        }

        var recipients = update.FailedLoginAlertRecipients is null
            ? null
            : EmailAddressRules.NormalizeRecipients(update.FailedLoginAlertRecipients);
        var normalized = update with { PublicAppUrl = publicUrl, FailedLoginAlertRecipients = recipients };
        var currentSettings = await settings.GetAsync(cancellationToken);
        var alertsEnabled = normalized.FailedLoginAlertEnabled ?? currentSettings?.FailedLoginAlertEnabled ?? false;
        var effectiveRecipients = normalized.FailedLoginAlertRecipients ?? currentSettings?.FailedLoginAlertRecipients ?? "";
        if (alertsEnabled)
        {
            if (effectiveRecipients.Length == 0)
            {
                throw new ArgumentException("Configure at least one failed login alert recipient before enabling alerts.");
            }
            if (!await settings.ActiveEmailProfileIsReadyAsync(cancellationToken))
            {
                throw new ArgumentException("Failed login alerts require the active SMTP profile to be enabled and complete.");
            }
        }

        await settings.SaveAsync(normalized, cancellationToken);
    }
}
