using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class DashboardQueriesTests
{
    [Fact]
    public async Task BoundsReadsAndFiltersSavedBriefsByTabGrant()
    {
        var store = new StubStore();
        var queries = new DashboardQueries(store);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetHazardsAsync(0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetHazardsAsync(101, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetThreatTrendsAsync(0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetThreatTrendsAsync(91, CancellationToken.None));

        var reader = new AuthenticatedUser(
            8,
            "viewer",
            "analyst",
            [],
            ["Tab: Dashboards -> Operational", "Tab: Dashboards -> Internal Risk"],
            []);
        var briefs = await queries.GetBriefsAsync(reader, CancellationToken.None);
        Assert.Equal("shift summary", briefs["rolling_summary"]);
        Assert.Null(briefs["internal_brief"]);
        Assert.DoesNotContain("global_brief", briefs.Keys);
        Assert.DoesNotContain("unified_brief", briefs.Keys);

        var admin = await queries.GetBriefsAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []), CancellationToken.None);
        Assert.Equal("global", admin["global_brief"]);
        Assert.Equal("unified", admin["unified_brief"]);
    }

    private sealed class StubStore : IOperationalDashboardStore
    {
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new DashboardMetrics(0, 0, 0, 0));

        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DashboardRegionalHazard>>([]);

        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyThreatScoreEntry>>([]);

        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<DashboardBriefSnapshot?>(new DashboardBriefSnapshot(
                "shift summary", DateTime.UtcNow,
                "global", DateTime.UtcNow,
                "AI failed to process batch.", DateTime.UtcNow,
                "unified", DateTime.UtcNow));

        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }
}
