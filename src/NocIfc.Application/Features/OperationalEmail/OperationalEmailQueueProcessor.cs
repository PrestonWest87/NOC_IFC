using System.Globalization;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed class OperationalEmailQueueProcessor(
    IOperationalEmailStore emailStore,
    IAiSmtpSettingsStore smtpSettings,
    IOperationalDashboardStore dashboard,
    IOperationalEmailSender emailSender)
{
    public async Task<int> ProcessDueAsync(
        DateTimeOffset nowUtc,
        int limit,
        CancellationToken cancellationToken)
    {
        var claimed = await emailStore.ClaimDueEmailsAsync(
            nowUtc.UtcDateTime, TimeSpan.FromMinutes(20), Math.Clamp(limit, 1, 25), cancellationToken);
        foreach (var emailId in claimed)
        {
            await DeliverAsync(emailId, cancellationToken);
        }
        return claimed.Count;
    }

    private async Task DeliverAsync(int emailId, CancellationToken cancellationToken)
    {
        var email = await emailStore.GetProcessingEmailAsync(emailId, cancellationToken)
            ?? throw new InvalidOperationException("Claimed operational email could not be loaded.");
        var fields = new Dictionary<string, string>(email.Fields, StringComparer.Ordinal);
        var body = email.Body;
        string? contentError = null;
        TimeOnly? recurrenceTime = null;
        if (email.ScheduleType is "daily" or "weekly")
        {
            if (!TimeOnly.TryParseExact(email.RecurrenceTime, "HH:mm", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var parsedTime))
            {
                contentError = "Recurring send time must use 24-hour HH:MM format.";
            }
            else if (email.ScheduleType == "weekly" && email.RecurrenceWeekday is not (>= 0 and <= 6))
            {
                contentError = "Choose a weekday from Monday through Sunday.";
            }
            else
            {
                recurrenceTime = parsedTime;
            }
        }

        if (OperationalEmailTemplateCatalog.Find(email.TemplateKey)?.LiveSource == "global_shift_analysis")
        {
            var latest = (await dashboard.GetBriefsAsync(cancellationToken))?.RollingSummary ?? "";
            fields["shift_analysis"] = latest;
            body = OperationalEmailSendCommands.AppendSignature(latest, email.SignatureContent)
                .Replace("\r\n", "\n").Replace('\r', '\n');
            if (string.IsNullOrWhiteSpace(latest) && contentError is null)
            {
                contentError = "No shift analysis is available in Global Dashboards yet.";
            }
            else if (body.Length > 200_000 && contentError is null)
            {
                contentError = "The latest shift analysis and signature exceed the 200,000-character email limit.";
            }
            await emailStore.UpdateProcessingEmailContentAsync(
                emailId, body, fields, DateTime.UtcNow, cancellationToken);
        }

        var settings = await smtpSettings.GetAsync(cancellationToken);
        var provider = string.IsNullOrWhiteSpace(settings?.ActiveSmtpProvider) ? "smtp" : settings.ActiveSmtpProvider;
        var sender = OperationalEmailRules.GlobalSenderRecipient(settings);
        var deliveryId = await emailStore.CreateDeliverySnapshotAsync(
            emailId, provider, sender, DateTime.UtcNow, cancellationToken);
        EmailSendResult delivery;
        if (contentError is not null)
        {
            delivery = new EmailSendResult(false, contentError);
        }
        else if (!EmailAddressRules.IsValid(sender))
        {
            delivery = new EmailSendResult(false,
                "Configure one valid global SMTP sender address in Settings > AI & SMTP.");
        }
        else
        {
            try
            {
                delivery = await emailSender.SendOperationalEmailAsync(
                    new OperationalEmailEnvelope(
                        email.ToRecipients,
                        email.CcRecipients,
                        email.BccRecipients,
                        email.Subject,
                        body,
                        OperationalEmailSendCommands.RenderHtmlAlternative(body, fields),
                        email.Attachments.Select(attachment => new EmailAttachment(
                            attachment.FileName, attachment.ContentType, attachment.Content)).ToArray()),
                    cancellationToken);
            }
            catch (Exception)
            {
                delivery = new EmailSendResult(false, "SMTP delivery failed.");
            }
        }

        var completedAt = DateTime.UtcNow;
        DateTime? nextRunAt = null;
        if (recurrenceTime is { } time)
        {
            nextRunAt = OperationalEmailScheduleRules.NextRecurrence(
                email.ScheduleType, time, email.RecurrenceWeekday,
                new DateTimeOffset(completedAt, TimeSpan.Zero));
        }
        await emailStore.CompleteDeliveryAsync(
            emailId, deliveryId, delivery.Success, delivery.Message, completedAt, nextRunAt, CancellationToken.None);
    }
}
