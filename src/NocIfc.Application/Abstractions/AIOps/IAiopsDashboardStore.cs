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
    Task<bool> AcknowledgeAlertsAsync(
        IReadOnlyList<int> alertIds,
        string username,
        DateTime acknowledgedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<bool> CanAccessAlertIdsAsync(
        IReadOnlyList<int> alertIds,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<bool> SetClusterDispatchAsync(
        IReadOnlyList<int> alertIds,
        bool isDispatched,
        string username,
        DateTime dispatchedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<AiopsNeedsDispatchUpdate> SetSiteNeedsDispatchAsync(
        string siteName,
        bool needsDispatch,
        string username,
        DateTime modifiedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<bool> SetSiteMaintenanceAsync(
        string siteName,
        bool isMaintenance,
        DateTime? maintenanceEtr,
        string? maintenanceReason,
        string username,
        DateTime modifiedAtUtc,
        CancellationToken cancellationToken);
    Task<AiopsSiteResolutionUpdate> ResolveSiteAsync(
        string siteName,
        string username,
        DateTime resolvedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
    Task<bool> ResolveAlertAsync(
        int alertId,
        string nodeName,
        DateTime resolvedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken);
}
