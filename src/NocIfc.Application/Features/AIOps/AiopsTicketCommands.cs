using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.AIOps;

public sealed record AiopsManualTicket(
    string? Site,
    string? Priority,
    string? TicketText,
    string? Recipient,
    IReadOnlyList<int> AlertIds,
    string? Sla);

public enum AiopsTicketScopeFailure
{
    None,
    Site,
    Alerts,
}

public sealed record AiopsTicketDeliveryResult(AiopsTicketScopeFailure ScopeFailure, EmailSendResult? Delivery);

public sealed class AiopsTicketCommands(
    FacilityDirectoryCommands facilities,
    IAiopsDashboardStore dashboard,
    IEmailSender emailSender)
{
    private const string DefaultRecipient = "remedyforceworkflow@aecc.com, noc@aecc.com";

    public async Task<AiopsTicketDeliveryResult> SendAsync(
        AuthenticatedUser user,
        AiopsManualTicket ticket,
        CancellationToken cancellationToken)
    {
        IReadOnlySet<string>? allowedSiteNames = user.IsAdministrator
            ? null
            : (await facilities.GetLocationsAsync(user, cancellationToken))
                .Where(location => !string.IsNullOrEmpty(location.Name))
                .Select(location => location.Name!)
                .ToHashSet(StringComparer.Ordinal);
        var site = ticket.Site ?? "";
        if (allowedSiteNames is not null && !allowedSiteNames.Contains(site))
        {
            return new AiopsTicketDeliveryResult(AiopsTicketScopeFailure.Site, null);
        }
        if (!await dashboard.CanAccessAlertIdsAsync(ticket.AlertIds, allowedSiteNames, cancellationToken))
        {
            return new AiopsTicketDeliveryResult(AiopsTicketScopeFailure.Alerts, null);
        }

        var priority = ticket.Priority ?? "P3";
        var message = await emailSender.SendPlainTextAsync(
            ticket.Recipient ?? DefaultRecipient,
            $"TICKET: {priority} Incident at {site}",
            $"*** MANUAL TICKET ***\nTarget SLA: {ticket.Sla ?? "N/A (Manual Dispatch)"}\n\n{ticket.TicketText ?? ""}",
            cancellationToken);
        if (message.Success && ticket.AlertIds.Count > 0)
        {
            // The alert set was site-validated before email; match the source's post-send state update.
            await dashboard.SetClusterDispatchAsync(
                ticket.AlertIds, true, user.Username, DateTime.UtcNow, null, cancellationToken);
        }
        return new AiopsTicketDeliveryResult(AiopsTicketScopeFailure.None, message);
    }
}
