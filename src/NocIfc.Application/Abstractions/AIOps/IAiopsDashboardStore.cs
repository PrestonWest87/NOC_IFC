using NocIfc.Domain.AIOps;

namespace NocIfc.Application.Abstractions.AIOps;

public interface IAiopsDashboardStore
{
    Task<IReadOnlyList<AiopsAlertEntry>> GetUnresolvedAlertsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<AiopsTimelineEventEntry>> GetTimelineEventsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<AiopsRegionalOutageEntry>> GetUnresolvedOutagesAsync(CancellationToken cancellationToken);
    Task<IReadOnlyDictionary<string, int>> GetActiveIssueCountsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
}
