using System.Globalization;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Dashboard;

public sealed class DashboardQueries(IOperationalDashboardStore dashboard)
{
    private static readonly string[] InternalBriefFailureMarkers =
    [
        "batch processing failure notice",
        "skeleton report",
        "must not be circulated as a complete risk assessment",
        "asset-level findings that should populate this brief are not available",
        "internal brief generation failed",
        "internal asset correlation failed; no complete brief was saved",
        "no internal asset or recent cve data is available for analysis",
        "ai failed to process batch",
    ];

    private static readonly Regex FailedUpstreamBatch = new(
        @"upstream\s+aiops\s+batch[\s\S]{0,240}failed\s+to\s+process",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public Task<DashboardMetrics> GetMetricsAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        return dashboard.GetMetricsAsync(now.AddDays(-1), now, cancellationToken);
    }

    public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(
        int limit,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 100.");
        }
        return dashboard.GetHazardsAsync(DateTime.UtcNow, limit, cancellationToken);
    }

    public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(
        int days,
        CancellationToken cancellationToken)
    {
        if (days is < 1 or > 90)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "days must be between 1 and 90.");
        }
        return dashboard.GetThreatTrendsAsync(DateTime.UtcNow.AddDays(-days), cancellationToken);
    }

    public async Task<IReadOnlyDictionary<string, object?>> GetBriefsAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var snapshot = await dashboard.GetBriefsAsync(cancellationToken);
        if (snapshot is null)
        {
            return new Dictionary<string, object?>();
        }

        var values = new Dictionary<string, object?>(StringComparer.Ordinal);
        Add("Tab: Dashboards -> Operational", "rolling_summary", snapshot.RollingSummary);
        Add("Tab: Dashboards -> Operational", "rolling_summary_time", FormatDate(snapshot.RollingSummaryTime));
        Add("Tab: Dashboards -> Global Risk", "global_brief", snapshot.GlobalBrief);
        Add("Tab: Dashboards -> Global Risk", "global_brief_time", FormatDate(snapshot.GlobalBriefTime));
        var internalBrief = IsInternalRiskBriefFailureNotice(snapshot.InternalBrief) ? null : snapshot.InternalBrief;
        Add("Tab: Dashboards -> Internal Risk", "internal_brief", internalBrief);
        Add("Tab: Dashboards -> Internal Risk", "internal_brief_time", FormatDate(snapshot.InternalBriefTime));
        Add("Tab: Dashboards -> Unified Brief", "unified_brief", snapshot.UnifiedBrief);
        Add("Tab: Dashboards -> Unified Brief", "unified_brief_time", FormatDate(snapshot.UnifiedBriefTime));
        return values;

        void Add(string permission, string key, object? value)
        {
            if (user.IsAdministrator || user.AllowedActions.Contains(permission, StringComparer.Ordinal))
            {
                values[key] = value;
            }
        }
    }

    internal static bool IsInternalRiskBriefFailureNotice(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return true;
        }
        var normalized = content.ToLowerInvariant();
        return InternalBriefFailureMarkers.Any(marker => normalized.Contains(marker, StringComparison.Ordinal))
            || FailedUpstreamBatch.IsMatch(normalized);
    }

    private static string? FormatDate(DateTime? date) =>
        date?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
