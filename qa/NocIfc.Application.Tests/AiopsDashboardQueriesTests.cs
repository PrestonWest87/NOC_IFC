using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiopsDashboardQueriesTests
{
    [Fact]
    public async Task FiltersBoardDataLocationsCountsAndInvestigatingSitesBySiteType()
    {
        var store = new StubDashboardStore
        {
            Alerts = [Alert(1, "Central NOC"), Alert(2, "Field Office")],
            Events =
            [
                new AiopsTimelineEventEntry(1, DateTime.UtcNow, "User", "Resolution", "Central update", "Central NOC"),
                new AiopsTimelineEventEntry(2, DateTime.UtcNow, "User", "Resolution", "Field update", "Field Office"),
                new AiopsTimelineEventEntry(3, DateTime.UtcNow, "System", "Notice", "Unscoped event", null),
            ],
            Outages = [Outage(1, "Power loss near Central NOC"), Outage(2, "Power loss near Field Office")],
            Counts = new Dictionary<string, int>(StringComparer.Ordinal)
            {
                ["Central NOC"] = 2,
                ["Field Office"] = 1,
            },
        };
        var investigating = new AiopsInvestigationState();
        investigating.Set("Central NOC", true);
        investigating.Set("Field Office", true);
        var facilities = new FacilityDirectoryCommands(new StubFacilityStore(
            [Location(1, "Central NOC", "NOC"), Location(2, "Field Office", "SOC")]));
        var queries = new AiopsDashboardQueries(store, facilities, investigating);
        var user = new AuthenticatedUser(9, "operator", "analyst", ["AIOps RCA"], [], ["NOC"]);

        var result = await queries.GetBoardAsync(user, CancellationToken.None);

        Assert.Equal(new[] { 1 }, result.Alerts.Select(alert => alert.Id));
        Assert.Equal(new[] { 1 }, result.Events.Select(item => item.Id));
        Assert.Equal(new[] { 1 }, result.Grid.Select(item => item.Id));
        Assert.Equal(2, result.ActiveIssueCounts["Central NOC"]);
        Assert.DoesNotContain("Field Office", result.ActiveIssueCounts.Keys);
        Assert.Equal(new[] { "Central NOC" }, result.Locations.Select(location => location.Name));
        Assert.Equal(new[] { "Central NOC" }, result.InvestigatingSites);
        Assert.False(result.IsAdministrator);
    }

    private static AiopsAlertEntry Alert(int id, string site) => new(
        id, "Down", "High", $"node-{id}", null, "Down", null, "details", null, null, site,
        DateTime.UtcNow, null, false, false, false, false, null, "Router", "network",
        null, null, null, null, null);

    private static AiopsRegionalOutageEntry Outage(int id, string affectedArea) => new(
        id, "Power", "Utility", "Outage", affectedArea, null, null, 10, DateTime.UtcNow, false);

    private static MonitoredLocationEntry Location(int id, string name, string type) => new(
        id, name, 34.8, -92.2, type, "Central", "P1-Critical", null, null, false,
        null, null, null, null, null, null, null, null);

    private sealed class StubDashboardStore : IAiopsDashboardStore
    {
        public IReadOnlyList<AiopsAlertEntry> Alerts { get; init; } = [];
        public IReadOnlyList<AiopsTimelineEventEntry> Events { get; init; } = [];
        public IReadOnlyList<AiopsRegionalOutageEntry> Outages { get; init; } = [];
        public IReadOnlyDictionary<string, int> Counts { get; init; } = new Dictionary<string, int>();

        public Task<IReadOnlyList<AiopsAlertEntry>> GetUnresolvedAlertsAsync(
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(Alerts);

        public Task<IReadOnlyList<AiopsTimelineEventEntry>> GetTimelineEventsAsync(
            IReadOnlySet<string>? allowedSiteNames,
            int limit,
            CancellationToken cancellationToken) => Task.FromResult(Events);

        public Task<IReadOnlyList<AiopsRegionalOutageEntry>> GetUnresolvedOutagesAsync(
            CancellationToken cancellationToken) => Task.FromResult(Outages);

        public Task<IReadOnlyDictionary<string, int>> GetActiveIssueCountsAsync(
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(Counts);

        public Task<bool> AcknowledgeAlertsAsync(
            IReadOnlyList<int> alertIds,
            string username,
            DateTime acknowledgedAtUtc,
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<bool> CanAccessAlertIdsAsync(
            IReadOnlyList<int> alertIds,
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<bool> SetClusterDispatchAsync(
            IReadOnlyList<int> alertIds,
            bool isDispatched,
            string username,
            DateTime dispatchedAtUtc,
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<AiopsNeedsDispatchUpdate> SetSiteNeedsDispatchAsync(
            string siteName,
            bool needsDispatch,
            string username,
            DateTime modifiedAtUtc,
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(
                new AiopsNeedsDispatchUpdate(AiopsNeedsDispatchOutcome.Updated, 0));

        public Task<bool> SetSiteMaintenanceAsync(
            string siteName,
            bool isMaintenance,
            DateTime? maintenanceEtr,
            string? maintenanceReason,
            string username,
            DateTime modifiedAtUtc,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<AiopsSiteResolutionUpdate> ResolveSiteAsync(
            string siteName,
            string username,
            DateTime resolvedAtUtc,
            IReadOnlySet<string>? allowedSiteNames,
            CancellationToken cancellationToken) => Task.FromResult(
                new AiopsSiteResolutionUpdate(AiopsSiteResolutionOutcome.Resolved, 0));
    }

    private sealed class StubFacilityStore(IReadOnlyList<MonitoredLocationEntry> locations) : IFacilityDirectoryStore
    {
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) => Task.FromResult(locations);
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) => Task.FromResult(locations);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(int locationId, IReadOnlyList<MonitoredLocationContactValue> contacts, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<int> ImportLocationsAsync(IReadOnlyList<MonitoredLocationImportRow> locations, string mode, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task UpdateLocationsAsync(IReadOnlyList<MonitoredLocationEditRow> locations, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
