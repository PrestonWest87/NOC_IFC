using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailCancellationResponse(string Status, int EmailId);

public sealed class OperationalEmailScheduleHistoryQueries(IOperationalEmailStore emailStore)
{
    public Task<IReadOnlyList<OperationalEmailScheduledEntry>> GetScheduledAsync(
        int limit,
        CancellationToken cancellationToken) =>
        emailStore.GetScheduledEmailsAsync(Math.Clamp(limit, 1, 250), cancellationToken);

    public Task<IReadOnlyList<OperationalEmailDeliveryHistoryEntry>> GetHistoryAsync(
        int limit,
        CancellationToken cancellationToken) =>
        emailStore.GetDeliveryHistoryAsync(Math.Clamp(limit, 1, 250), cancellationToken);

    public Task<OperationalEmailDeliveryDetail?> GetDeliveryAsync(
        int deliveryId,
        CancellationToken cancellationToken) =>
        emailStore.GetDeliveryDetailAsync(deliveryId, cancellationToken);

    public Task<IReadOnlyList<OperationalEmailSourceGroup>> GetMaintenanceNoticesAsync(
        int limit,
        CancellationToken cancellationToken) =>
        emailStore.GetSentSourceGroupsAsync(
            OperationalEmailTemplateCatalog.MaintenanceSourceKeys,
            Math.Clamp(limit, 1, 250),
            cancellationToken);

    public Task<IReadOnlyList<OperationalEmailSourceGroup>> GetFiberOutagesAsync(
        int limit,
        CancellationToken cancellationToken) =>
        emailStore.GetSentSourceGroupsAsync(
            OperationalEmailTemplateCatalog.FiberOutageSourceKeys,
            Math.Clamp(limit, 1, 250),
            cancellationToken);

    public async Task<OperationalEmailCancellationResponse> CancelAsync(
        int emailId,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        if (emailId <= 0) throw new KeyNotFoundException("Scheduled email was not found.");
        var result = await emailStore.CancelScheduledEmailAsync(
            emailId, actorUserId, DateTime.UtcNow, cancellationToken);
        return result switch
        {
            OperationalEmailCancellationResult.Cancelled => new OperationalEmailCancellationResponse("cancelled", emailId),
            OperationalEmailCancellationResult.NotFound => throw new KeyNotFoundException("Scheduled email was not found."),
            OperationalEmailCancellationResult.InProgress => throw new InvalidOperationException("This email is being sent and cannot be cancelled now."),
            _ => throw new InvalidOperationException("This email is no longer scheduled."),
        };
    }
}
