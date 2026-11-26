using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.AIOps;

public sealed record AiopsScopedDashboardInputs(
    IReadOnlyList<AiopsAlertEntry> Alerts,
    IReadOnlyList<AiopsTimelineEventEntry> Events,
    IReadOnlyList<MonitoredLocationEntry> Locations,
    IReadOnlySet<string>? AllowedSiteNames,
    bool IsAdministrator);

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
        var inputs = await GetScopedInputsAsync(user, cancellationToken);
        var outages = await dashboard.GetUnresolvedOutagesAsync(cancellationToken);
        var grid = inputs.AllowedSiteNames is null
            ? outages
            : outages.Where(outage => inputs.AllowedSiteNames.Any(site =>
                (outage.AffectedArea ?? "").Contains(site, StringComparison.OrdinalIgnoreCase))).ToArray();
        var activeIssueCounts = await dashboard.GetActiveIssueCountsAsync(inputs.AllowedSiteNames, cancellationToken);
        if (inputs.AllowedSiteNames is not null)
        {
            activeIssueCounts = activeIssueCounts
                .Where(pair => inputs.AllowedSiteNames.Contains(pair.Key))
                .ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        }
        var investigatingSites = investigating.GetSites();
        if (inputs.AllowedSiteNames is not null)
        {
            investigatingSites = investigatingSites.Where(inputs.AllowedSiteNames.Contains).ToArray();
        }
        return new AiopsBoardSnapshot(
            inputs.Alerts,
            inputs.Events,
            grid,
            activeIssueCounts,
            inputs.Locations,
            investigatingSites,
            inputs.IsAdministrator);
    }

    public async Task<AiopsScopedDashboardInputs> GetScopedInputsAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var locations = await facilities.GetLocationsAsync(user, cancellationToken);
        IReadOnlySet<string>? allowedSiteNames = user.IsAdministrator
            ? null
            : GetSiteNames(locations);
        var alerts = await dashboard.GetUnresolvedAlertsAsync(allowedSiteNames, cancellationToken);
        var events = await dashboard.GetTimelineEventsAsync(allowedSiteNames, 50, cancellationToken);
        if (allowedSiteNames is not null)
        {
            alerts = alerts.Where(alert => alert.MappedLocation is not null && allowedSiteNames.Contains(alert.MappedLocation)).ToArray();
            events = events.Where(timelineEvent => timelineEvent.SiteName is not null
                && allowedSiteNames.Contains(timelineEvent.SiteName)).ToArray();
        }
        return new AiopsScopedDashboardInputs(alerts, events, locations, allowedSiteNames, user.IsAdministrator);
    }

    public async Task<bool> AcknowledgeAlertsAsync(
        AuthenticatedUser user,
        IReadOnlyList<int> alertIds,
        CancellationToken cancellationToken)
    {
        var allowedSiteNames = await GetAllowedSiteNamesAsync(user, cancellationToken);
        return await dashboard.AcknowledgeAlertsAsync(
            alertIds, user.Username, DateTime.UtcNow, allowedSiteNames, cancellationToken);
    }

    public async Task<bool> SetClusterDispatchAsync(
        AuthenticatedUser user,
        IReadOnlyList<int> alertIds,
        bool isDispatched,
        CancellationToken cancellationToken)
    {
        var allowedSiteNames = await GetAllowedSiteNamesAsync(user, cancellationToken);
        return await dashboard.SetClusterDispatchAsync(
            alertIds, isDispatched, user.Username, DateTime.UtcNow, allowedSiteNames, cancellationToken);
    }

    public async Task<AiopsNeedsDispatchUpdate> SetSiteNeedsDispatchAsync(
        AuthenticatedUser user,
        string siteName,
        bool needsDispatch,
        CancellationToken cancellationToken)
    {
        var allowedSiteNames = await GetAllowedSiteNamesAsync(user, cancellationToken);
        return await dashboard.SetSiteNeedsDispatchAsync(
            siteName, needsDispatch, user.Username, DateTime.UtcNow, allowedSiteNames, cancellationToken);
    }

    private async Task<IReadOnlySet<string>?> GetAllowedSiteNamesAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken) =>
        user.IsAdministrator
            ? null
            : GetSiteNames(await facilities.GetLocationsAsync(user, cancellationToken));

    private static IReadOnlySet<string> GetSiteNames(IReadOnlyList<MonitoredLocationEntry> locations) =>
        locations.Where(location => !string.IsNullOrEmpty(location.Name))
            .Select(location => location.Name!)
            .ToHashSet(StringComparer.Ordinal);
}
