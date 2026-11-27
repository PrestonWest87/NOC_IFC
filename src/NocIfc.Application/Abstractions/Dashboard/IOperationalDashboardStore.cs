using NocIfc.Domain.Dashboard;

namespace NocIfc.Application.Abstractions.Dashboard;

public interface IOperationalDashboardStore
{
    Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken);
    Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken);
    Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken);
    Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken);
    Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken);
    Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken);
}
