using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.AIOps;

public sealed class AiopsDashboardQueries(
    IAiopsDashboardStore dashboard,
    FacilityDirectoryCommands facilities,
    AiopsInvestigationState investigating)
{
    public async Task<IReadOnlyList<MonitoredLocationEntry>> GetSitesAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken) =>
        await facilities.GetLocationsAsync(user, cancellationToken);

    public async Task<AiopsBoardSnapshot> GetBoardAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var locations = await facilities.GetLocationsAsync(user, cancellationToken);
        IReadOnlySet<string>? allowedSiteNames = user.IsAdministrator
            ? null
            : locations.Where(location => !string.IsNullOrEmpty(location.Name))
                .Select(location => location.Name!)
                .ToHashSet(StringComparer.Ordinal);
        var alerts = await dashboard.GetUnresolvedAlertsAsync(allowedSiteNames, cancellationToken);
        var events = await dashboard.GetTimelineEventsAsync(allowedSiteNames, 50, cancellationToken);
        var outages = await dashboard.GetUnresolvedOutagesAsync(cancellationToken);
        var grid = allowedSiteNames is null
            ? outages
            : outages.Where(outage => allowedSiteNames.Any(site =>
                (outage.AffectedArea ?? "").Contains(site, StringComparison.OrdinalIgnoreCase))).ToArray();
        var activeIssueCounts = await dashboard.GetActiveIssueCountsAsync(allowedSiteNames, cancellationToken);
        var investigatingSites = investigating.GetSites();
        if (allowedSiteNames is not null)
        {
            alerts = alerts.Where(alert => alert.MappedLocation is not null && allowedSiteNames.Contains(alert.MappedLocation)).ToArray();
            events = events.Where(timelineEvent => timelineEvent.SiteName is not null
                && allowedSiteNames.Contains(timelineEvent.SiteName)).ToArray();
            activeIssueCounts = activeIssueCounts
                .Where(pair => allowedSiteNames.Contains(pair.Key))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
            investigatingSites = investigatingSites.Where(allowedSiteNames.Contains).ToArray();
        }
        return new AiopsBoardSnapshot(
            alerts, events, grid, activeIssueCounts, locations, investigatingSites, user.IsAdministrator);
    }
}
