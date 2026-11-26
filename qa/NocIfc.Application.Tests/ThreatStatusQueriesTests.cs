using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ThreatStatusQueriesTests
{
    [Fact]
    public async Task BoundsCloudAndCrimeQueriesBeforePersistence()
    {
        var store = new StubStore();
        var queries = new ThreatStatusQueries(store);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetCloudOutagesAsync(true, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetCloudOutagesAsync(true, 91, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentCrimesAsync(0, 1, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentCrimesAsync(169, 1, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentCrimesAsync(24, 0.09, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentCrimesAsync(24, double.PositiveInfinity, CancellationToken.None));
        Assert.Equal(0, store.CloudCalls);
        Assert.Equal(0, store.CrimeCalls);

        await queries.GetCloudOutagesAsync(false, 12, CancellationToken.None);
        await queries.GetRecentCrimesAsync(24, 1.5, CancellationToken.None);
        Assert.Equal(1, store.CloudCalls);
        Assert.False(store.ActiveOnly);
        Assert.Equal(12, store.CloudCutoffDays);
        Assert.Equal(1, store.CrimeCalls);
        Assert.Equal(1.5, store.MaxDistance);
        Assert.Equal(24, store.CrimeCutoffHours);
    }

    [Fact]
    public async Task MapsCurrentMicrosoftFeedIncidentsToConfiguredServices()
    {
        var now = DateTime.UtcNow;
        var store = new StubStore
        {
            Snapshot = new Microsoft365StatusSnapshot(
                new Microsoft365FeedState(now, now, 123, 200, null),
                true,
                8,
                [new CloudOutageEntry(4, "Microsoft 365", "Exchange", "Outlook issue", "Exchange Online sign-in failures", "https://status.example/incidents/4", false, now.AddMinutes(-2), "external-4", "ServiceDegradation")]),
        };
        var report = await new ThreatStatusQueries(store).GetMicrosoft365StatusAsync(CancellationToken.None);

        Assert.Equal("current", report.FeedStatus);
        Assert.Equal(29, report.StaleAfterMinutes);
        Assert.Equal(4, Assert.Single(report.ActiveIncidents).Id);
        var outlook = report.Services.Single(service => service.Id == "outlook");
        Assert.Equal("incident", outlook.Status);
        Assert.Equal("Service degradation", outlook.StatusLabel);
        Assert.Single(outlook.ActiveIncidents);
        Assert.EndsWith("Z", outlook.ActiveIncidents[0].UpdatedAt, StringComparison.Ordinal);
        var teams = report.Services.Single(service => service.Id == "teams");
        Assert.Equal("no_active_incident", teams.Status);
    }

    [Fact]
    public async Task DistinguishesUnavailableStaleDegradedAndDisabledMicrosoftFeeds()
    {
        var unknown = await GetReport(new Microsoft365StatusSnapshot(null, null, null, []));
        Assert.Equal("unknown", unknown.FeedStatus);

        var stale = await GetReport(new Microsoft365StatusSnapshot(
            new Microsoft365FeedState(DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(-1), 3, 200, null),
            true, 8, []));
        Assert.Equal("stale", stale.FeedStatus);
        Assert.All(stale.Services, service => Assert.Equal("unknown", service.Status));

        var degraded = await GetReport(new Microsoft365StatusSnapshot(
            new Microsoft365FeedState(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(-1), 3, 500, "poll failed"),
            true, 8, []));
        Assert.Equal("degraded", degraded.FeedStatus);
        Assert.All(degraded.Services, service => Assert.Equal("no_active_incident", service.Status));

        var disabled = await GetReport(new Microsoft365StatusSnapshot(
            new Microsoft365FeedState(DateTime.UtcNow, DateTime.UtcNow, 3, 200, null), false, 8, []));
        Assert.Equal("disabled", disabled.FeedStatus);
        Assert.All(disabled.Services, service => Assert.Equal("Monitoring disabled", service.StatusLabel));
    }

    private static Task<Microsoft365StatusReport> GetReport(Microsoft365StatusSnapshot snapshot) =>
        new ThreatStatusQueries(new StubStore { Snapshot = snapshot }).GetMicrosoft365StatusAsync(CancellationToken.None);

    private sealed class StubStore : IThreatStatusStore
    {
        public int CloudCalls { get; private set; }
        public bool ActiveOnly { get; private set; }
        public int CloudCutoffDays { get; private set; }
        public int CrimeCalls { get; private set; }
        public double MaxDistance { get; private set; }
        public int CrimeCutoffHours { get; private set; }
        public Microsoft365StatusSnapshot Snapshot { get; init; } = new(null, null, null, []);

        public Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(
            bool activeOnly,
            DateTime updatedAfterUtc,
            CancellationToken cancellationToken)
        {
            CloudCalls++;
            ActiveOnly = activeOnly;
            CloudCutoffDays = (int)Math.Round((DateTime.UtcNow - updatedAfterUtc).TotalDays);
            return Task.FromResult<IReadOnlyList<CloudOutageEntry>>([]);
        }

        public Task<IReadOnlyList<CrimeIncidentEntry>> GetRecentCrimesAsync(
            double maxDistance,
            DateTime occurredAfterUtc,
            CancellationToken cancellationToken)
        {
            CrimeCalls++;
            MaxDistance = maxDistance;
            CrimeCutoffHours = (int)Math.Round((DateTime.UtcNow - occurredAfterUtc).TotalHours);
            return Task.FromResult<IReadOnlyList<CrimeIncidentEntry>>([]);
        }

        public Task<Microsoft365StatusSnapshot> GetMicrosoft365StatusAsync(
            DateTime updatedAfterUtc,
            CancellationToken cancellationToken) => Task.FromResult(Snapshot);
    }
}
