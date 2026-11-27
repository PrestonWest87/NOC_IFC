namespace NocIfc.Application.Abstractions.AIOps;

public interface IAutoEscalationStore
{
    Task<bool> IsNodeOnCooldownAsync(
        int alertId,
        string nodeName,
        string? siteName,
        DateTime cooldownCutoffUtc,
        CancellationToken cancellationToken);
    Task<bool> IsNodePagedAsync(
        string siteName,
        string? nodeName,
        int alertId,
        CancellationToken cancellationToken);
    Task<int> MarkTicketedAsync(IReadOnlyList<int> alertIds, CancellationToken cancellationToken);
    Task<int> MarkPageSentAsync(
        string siteName,
        string? nodeName,
        int alertId,
        DateTime sentAtUtc,
        CancellationToken cancellationToken);
}
