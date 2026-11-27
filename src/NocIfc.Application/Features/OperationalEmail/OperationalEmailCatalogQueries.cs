using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.OperationalEmail;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailTemplateView(
    string Key,
    string Label,
    string Description,
    IReadOnlyList<OperationalEmailTemplateField> Fields,
    bool AllowsBcc,
    bool AllowsCc,
    bool AllowsAttachments,
    string DefaultSubject,
    string DefaultBody,
    string DefaultTo,
    string DefaultCc,
    string DefaultBcc,
    DateTime? UpdatedAt);

public sealed record OperationalEmailAttachmentLimits(int MaxAttachments, int MaxBytesEach, int MaxBytesTotal);

public sealed record OperationalEmailTemplatesResult(
    IReadOnlyList<OperationalEmailTemplateView> Templates,
    string SenderAddress,
    string SmtpProvider,
    bool SmtpEnabled,
    string Timezone,
    string TimezoneAbbreviation,
    string LatestShiftAnalysis,
    DateTime? LatestShiftAnalysisTime,
    OperationalEmailAttachmentLimits AttachmentLimits);

public sealed record OperationalEmailReferenceData(
    IReadOnlyList<FiberEmailContactEntry> FiberContacts,
    IReadOnlyList<OnpageEmailContactEntry> OnpageContacts,
    IReadOnlyList<NetworkOrderCircuitEntry> NetworkOrders);

public sealed class OperationalEmailCatalogQueries(
    IOperationalEmailStore emailStore,
    ISettingsReferenceDirectoryStore directories,
    IAiSmtpSettingsStore aiSettings,
    IOperationalDashboardStore dashboardStore)
{
    private const string EmailTimezone = "America/Chicago";
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById(EmailTimezone);

    public async Task<OperationalEmailTemplatesResult> GetTemplatesAsync(CancellationToken cancellationToken)
    {
        await emailStore.EnsureTemplateDefaultsAsync(
            OperationalEmailTemplateCatalog.All.Select(template => new OperationalEmailTemplateDefault(
                template.Key, template.Label, template.Description, template.DefaultSubject, template.DefaultBody,
                "", "", "", null)).ToArray(), cancellationToken);
        var saved = (await emailStore.GetTemplateDefaultsAsync(cancellationToken))
            .ToDictionary(template => template.TemplateKey, StringComparer.Ordinal);
        var settings = await aiSettings.GetAsync(cancellationToken);
        var provider = string.IsNullOrEmpty(settings?.ActiveSmtpProvider) ? "smtp" : settings.ActiveSmtpProvider;
        var sender = provider switch
        {
            "gmail" => string.IsNullOrEmpty(settings?.GmailSmtpSender)
                ? settings?.GmailSmtpUsername ?? ""
                : settings.GmailSmtpSender,
            "smtp" => settings?.SmtpSender ?? "",
            _ => "",
        };
        var senderRecipient = OperationalEmailRules.ParseAddress(sender);
        var smtpEnabled = provider switch
        {
            "smtp" => settings?.SmtpEnabled == true && !string.IsNullOrWhiteSpace(settings.SmtpServer)
                && !string.IsNullOrWhiteSpace(sender),
            "gmail" => settings?.GmailSmtpEnabled == true && !string.IsNullOrWhiteSpace(settings.GmailSmtpUsername)
                && settings.GmailSmtpClientIdConfigured && settings.GmailSmtpClientSecretConfigured
                && settings.GmailSmtpRefreshTokenConfigured && !string.IsNullOrWhiteSpace(sender),
            _ => false,
        };

        var templates = new List<OperationalEmailTemplateView>(OperationalEmailTemplateCatalog.All.Count);
        foreach (var definition in OperationalEmailTemplateCatalog.All)
        {
            if (!saved.TryGetValue(definition.Key, out var row)) continue;
            var defaultCc = row.DefaultCc;
            if (definition.Key == OperationalEmailTemplateCatalog.FiberMaintenanceKey)
            {
                defaultCc = OperationalEmailRules.JoinUnique([senderRecipient, .. OperationalEmailRules.NormalizeRecipients(row.DefaultCc)]);
            }
            else if (definition.Key == OperationalEmailTemplateCatalog.FiberOnpageKey)
            {
                defaultCc = senderRecipient;
            }
            var defaultTo = OperationalEmailTemplateCatalog.FiberSenderToKeys.Contains(definition.Key)
                ? senderRecipient
                : definition.Key is OperationalEmailTemplateCatalog.FiberMaintenanceKey or OperationalEmailTemplateCatalog.FiberOnpageKey
                    ? ""
                    : row.DefaultTo;
            templates.Add(new OperationalEmailTemplateView(
                definition.Key,
                definition.Label,
                definition.Description,
                definition.Fields,
                definition.AllowsBcc,
                definition.AllowsCc,
                definition.AllowsAttachments,
                row.DefaultSubject,
                row.DefaultBody,
                defaultTo,
                defaultCc,
                definition.AllowsBcc ? row.DefaultBcc : "",
                row.UpdatedAt));
        }

        var dashboard = await dashboardStore.GetBriefsAsync(cancellationToken);
        var local = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
        var timezoneAbbreviation = CentralTimeZone.IsDaylightSavingTime(local) ? "CDT" : "CST";
        return new OperationalEmailTemplatesResult(
            templates,
            sender,
            provider,
            smtpEnabled,
            EmailTimezone,
            timezoneAbbreviation,
            dashboard?.RollingSummary ?? "",
            dashboard?.RollingSummaryTime,
            new OperationalEmailAttachmentLimits(5, 5 * 1024 * 1024, 20 * 1024 * 1024));
    }

    public async Task<OperationalEmailReferenceData> GetReferenceDataAsync(
        bool includeOnpage,
        CancellationToken cancellationToken)
    {
        var fiber = await directories.GetFiberAsync(cancellationToken);
        var onpage = includeOnpage
            ? await directories.GetOnpageAsync(cancellationToken)
            : Array.Empty<OnpageEmailContactEntry>();
        var orders = await directories.GetNetworkOrdersAsync(cancellationToken);
        return new OperationalEmailReferenceData(fiber, onpage, orders);
    }

    public Task<IReadOnlyList<OperationalEmailSignatureEntry>> GetSignaturesAsync(
        bool includeInactive,
        CancellationToken cancellationToken) =>
        emailStore.GetSignaturesAsync(includeInactive, cancellationToken);

}
