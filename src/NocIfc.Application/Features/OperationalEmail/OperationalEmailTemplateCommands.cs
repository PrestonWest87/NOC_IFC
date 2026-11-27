using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailTemplateUpdateResult(string Status, string TemplateKey);

public sealed class OperationalEmailTemplateCommands(
    IOperationalEmailStore emailStore,
    IAiSmtpSettingsStore aiSettings)
{
    private static readonly HashSet<string> AllowedFields = new(
        ["default_subject", "default_body", "default_to", "default_cc", "default_bcc"], StringComparer.Ordinal);

    public async Task<OperationalEmailTemplateUpdateResult> UpdateAsync(
        string templateKey,
        IReadOnlyDictionary<string, string> values,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        var definition = OperationalEmailTemplateCatalog.Find(templateKey)
            ?? throw new ArgumentException("Unknown operational email template.");
        var unknown = values.Keys.Where(key => !AllowedFields.Contains(key))
            .OrderBy(key => key, StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported template field(s): {string.Join(", ", unknown)}.");
        }
        if (values.Count == 0)
        {
            throw new ArgumentException("Provide at least one template default to update.");
        }
        if (OperationalEmailTemplateCatalog.FiberSenderToKeys.Contains(templateKey) && values.ContainsKey("default_to"))
        {
            throw new ArgumentException("Fiber email To defaults to the active Global From address.");
        }
        if (templateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey && values.ContainsKey("default_to"))
        {
            throw new ArgumentException("Fiber Maintenance To recipients are selected from the company contact directory.");
        }
        if (templateKey == OperationalEmailTemplateCatalog.FiberOnpageKey
            && (values.ContainsKey("default_to") || values.ContainsKey("default_cc")))
        {
            throw new ArgumentException("Fiber Outage ONPAGE To/Cc recipients are selected by the composer and Global From profile.");
        }

        var normalized = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var field in new[] { "default_subject", "default_body" })
        {
            if (!values.TryGetValue(field, out var value)) continue;
            var label = field == "default_subject" ? "Default subject" : "Default body";
            value = OperationalEmailRules.ValidateTemplateText(definition, value, label);
            if (templateKey == "morning_report" && field == "default_body" && value != "{{shift_analysis}}")
            {
                throw new ArgumentException("Morning Report body is sourced directly from the latest Global Dashboard shift analysis.");
            }
            if (templateKey == "morning_report" && field == "default_subject"
                && OperationalEmailRules.ContainsTemplateTokens(value))
            {
                throw new ArgumentException("Morning Report subject must be static and cannot contain date/title placeholders.");
            }
            normalized[field] = value;
        }

        string? globalSender = null;
        foreach (var field in new[] { "default_to", "default_cc", "default_bcc" })
        {
            if (!values.TryGetValue(field, out var value)) continue;
            if (!definition.AllowsCc && field != "default_to")
            {
                if (OperationalEmailRules.NormalizeRecipients(value).Length > 0)
                {
                    throw new ArgumentException("After-Hours ONPAGE supports To recipients only.");
                }
                normalized[field] = "";
                continue;
            }
            if (field == "default_bcc" && !definition.AllowsBcc)
            {
                throw new ArgumentException("This email template does not support BCC recipients.");
            }
            var recipients = OperationalEmailRules.NormalizeRecipients(value);
            if (templateKey == OperationalEmailTemplateCatalog.FiberMaintenanceKey && field == "default_cc")
            {
                globalSender ??= OperationalEmailRules.GlobalSenderRecipient(
                    await aiSettings.GetAsync(cancellationToken));
                recipients = recipients.Where(recipient =>
                    !recipient.Equals(globalSender, StringComparison.OrdinalIgnoreCase)).ToArray();
            }
            normalized[field] = string.Join(", ", recipients);
        }

        await emailStore.EnsureTemplateDefaultsAsync(
            OperationalEmailTemplateCatalog.All.Select(template => new OperationalEmailTemplateDefault(
                template.Key, template.Label, template.Description, template.DefaultSubject, template.DefaultBody,
                "", "", "", null)).ToArray(), cancellationToken);
        if (!await emailStore.UpdateTemplateDefaultsAsync(templateKey, normalized, actorUserId, cancellationToken))
        {
            throw new ArgumentException("Operational email template is not initialized.");
        }
        return new OperationalEmailTemplateUpdateResult("updated", templateKey);
    }
}
