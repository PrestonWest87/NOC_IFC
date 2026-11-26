using System.Globalization;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class ThreatStatusQueries(IThreatStatusStore status)
{
    private const string MicrosoftFeedUrl = "https://status.cloud.microsoft/api/feed/mac";
    private static readonly IReadOnlyDictionary<string, string> StatusLabels = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["investigating"] = "Investigating",
        ["servicedegradation"] = "Service degradation",
        ["serviceinterruption"] = "Service interruption",
        ["restoringservice"] = "Restoring service",
        ["extendedrecovery"] = "Extended recovery",
        ["verifyingservice"] = "Verifying service",
        ["investigationsuspended"] = "Investigation suspended",
        ["confirmed"] = "Confirmed incident",
        ["reported"] = "Reported",
    };

    private static readonly ServiceDefinition[] MicrosoftServices =
    [
        new("outlook", "Outlook / Exchange Online", ["exchange online", "outlook"]),
        new("teams", "Microsoft Teams", ["microsoft teams", "teams"]),
        new("sharepoint", "SharePoint Online", ["sharepoint"]),
        new("onedrive", "OneDrive for Business", ["onedrive"]),
        new("office_apps", "Microsoft 365 Apps / Office for the web", ["microsoft 365 apps", "office for the web", "office online"]),
        new("admin_center", "Microsoft 365 Admin Center", ["admin center"]),
        new("entra", "Microsoft Entra ID", ["entra id", "identity service", "azure active directory"]),
        new("defender", "Microsoft Defender XDR", ["microsoft defender", "defender xdr"]),
        new("power_platform", "Power Platform", ["power platform"]),
        new("microsoft_365", "Microsoft 365 overall", ["microsoft 365 services", "microsoft 365 suite", "multiple microsoft 365"]),
    ];

    public Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(
        bool activeOnly,
        int daysBack,
        CancellationToken cancellationToken)
    {
        if (daysBack is < 1 or > 90)
        {
            throw new ArgumentOutOfRangeException(nameof(daysBack), "days_back must be between 1 and 90.");
        }
        return status.GetCloudOutagesAsync(activeOnly, DateTime.UtcNow.AddDays(-daysBack), cancellationToken);
    }

    public Task<IReadOnlyList<CrimeIncidentEntry>> GetRecentCrimesAsync(
        int hoursBack,
        double maxDistance,
        CancellationToken cancellationToken)
    {
        if (hoursBack is < 1 or > 168)
        {
            throw new ArgumentOutOfRangeException(nameof(hoursBack), "hours_back must be between 1 and 168.");
        }
        if (!double.IsFinite(maxDistance) || maxDistance < 0.1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxDistance), "max_distance must be at least 0.1.");
        }
        return status.GetRecentCrimesAsync(
            maxDistance, DateTime.UtcNow.AddHours(-hoursBack), cancellationToken);
    }

    public async Task<Microsoft365StatusReport> GetMicrosoft365StatusAsync(CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var snapshot = await status.GetMicrosoft365StatusAsync(now.AddDays(-7), cancellationToken);
        var cloudJob = SchedulerSettingsCommands.Registry.Single(job => job.Key == "cloud_outages");
        var jobEnabled = snapshot.CloudJobEnabled ?? cloudJob.DefaultSchedule.Enabled;
        var intervalMinutes = snapshot.CloudJobIntervalMinutes is > 0
            ? snapshot.CloudJobIntervalMinutes.Value
            : cloudJob.DefaultSchedule.EveryValue ?? 8;
        var staleAfterMinutes = Math.Max(25, intervalMinutes * 3 + 5);
        var state = snapshot.FeedState;
        var lastAttempt = state?.LastAttemptAt;
        var lastSuccess = state?.LastSuccessAt;
        string feedStatus;
        if (!jobEnabled)
        {
            feedStatus = "disabled";
        }
        else if (lastSuccess is null)
        {
            feedStatus = string.IsNullOrEmpty(state?.LastError) ? "unknown" : "error";
        }
        else if ((now - lastSuccess.Value).TotalSeconds > staleAfterMinutes * 60)
        {
            feedStatus = "stale";
        }
        else if (!string.IsNullOrEmpty(state?.LastError) && lastAttempt > lastSuccess)
        {
            feedStatus = "degraded";
        }
        else
        {
            feedStatus = "current";
        }

        var incidents = snapshot.ActiveIncidents.Select(ToIncident).ToArray();
        var sourceIsCurrent = feedStatus is "current" or "degraded";
        var serviceStatuses = MicrosoftServices.Select(definition =>
        {
            var matching = snapshot.ActiveIncidents
                .Zip(incidents)
                .Where(pair => definition.Terms.Any(term =>
                    $"{pair.First.Title ?? ""} {pair.First.Description ?? ""}"
                        .Contains(term, StringComparison.OrdinalIgnoreCase)))
                .Select(pair => pair.Second)
                .ToArray();

            string serviceStatus;
            string statusLabel;
            if (!sourceIsCurrent)
            {
                serviceStatus = "unknown";
                statusLabel = feedStatus switch
                {
                    "disabled" => "Monitoring disabled",
                    "unknown" or "error" => "Feed status unavailable",
                    _ => "Feed is stale",
                };
            }
            else if (matching.Length > 0)
            {
                serviceStatus = "incident";
                statusLabel = matching[0].StatusLabel;
            }
            else
            {
                serviceStatus = "no_active_incident";
                statusLabel = "No active incident reported";
            }
            return new Microsoft365ServiceStatus(definition.Id, definition.Name, serviceStatus, statusLabel, matching);
        }).ToArray();

        return new Microsoft365StatusReport(
            "Microsoft 365 public service-health feed",
            "https://status.cloud.microsoft/",
            MicrosoftFeedUrl,
            feedStatus,
            ToIsoUtc(lastAttempt),
            ToIsoUtc(lastSuccess),
            state?.LastDurationMs,
            state?.LastHttpStatus,
            state?.LastError,
            staleAfterMinutes,
            serviceStatuses,
            incidents);
    }

    private static Microsoft365ActiveIncident ToIncident(CloudOutageEntry row)
    {
        var statusKey = new string((row.StatusCode ?? "")
            .ToLowerInvariant()
            .Where(character => character is >= 'a' and <= 'z')
            .ToArray());
        return new Microsoft365ActiveIncident(
            row.Id,
            row.Title ?? "Microsoft 365 service incident",
            row.Service ?? "Microsoft 365",
            row.Description ?? "",
            row.Link ?? "https://status.cloud.microsoft/",
            row.StatusCode ?? "",
            StatusLabels.GetValueOrDefault(statusKey, "Active incident"),
            ToIsoUtc(row.UpdatedAt));
    }

    private static string? ToIsoUtc(DateTime? value) => value is null
        ? null
        : value.Value.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);

    private sealed record ServiceDefinition(string Id, string Name, IReadOnlyList<string> Terms);
}
