using NocIfc.Application.Abstractions.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed class DangerZoneCommands(IDangerZoneStore store)
{
    private static readonly IReadOnlyDictionary<string, string> DeleteRecordTables =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Keyword"] = "keywords",
            ["FeedSource"] = "feed_sources",
            ["User"] = "users",
            ["Role"] = "roles",
            ["SavedReport"] = "saved_reports",
        };

    private static readonly IReadOnlyDictionary<string, string> ClearableTables =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["CloudOutage"] = "cloud_outages",
            ["MonitoredLocation"] = "monitored_locations",
            ["Article"] = "articles",
            ["ExtractedIOC"] = "extracted_iocs",
            ["FeedSource"] = "feed_sources",
            ["Keyword"] = "keywords",
        };

    public Task DeleteRecordAsync(string modelName, int recordId, CancellationToken cancellationToken)
    {
        if (recordId <= 0) throw new ArgumentException("Record ID must be positive.");
        if (!DeleteRecordTables.TryGetValue(modelName, out var table))
        {
            throw new ArgumentException("Model is not available for deletion.");
        }
        return store.DeleteRecordAsync(table, recordId, cancellationToken);
    }

    public Task ClearTablesAsync(IReadOnlyList<string> modelNames, CancellationToken cancellationToken)
    {
        var tables = modelNames.Where(ClearableTables.ContainsKey)
            .Select(name => ClearableTables[name])
            .Distinct(StringComparer.Ordinal).ToArray();
        return store.ClearTablesAsync(tables, cancellationToken);
    }

    public Task ClearCrimeDataAsync(CancellationToken cancellationToken) =>
        store.ClearCrimeDataAsync(cancellationToken);

    public Task ClearWeatherDataAsync(CancellationToken cancellationToken) =>
        store.ClearWeatherDataAsync(cancellationToken);

    public Task ClearTimelineEventsAsync(CancellationToken cancellationToken) =>
        store.ClearTimelineEventsAsync(cancellationToken);

    public Task ClearActiveAlertsAsync(CancellationToken cancellationToken) =>
        store.ClearActiveAlertsAsync(cancellationToken);

    public Task RunDatabaseMaintenanceAsync(CancellationToken cancellationToken) =>
        store.RunDatabaseMaintenanceAsync(DateTime.UtcNow, cancellationToken);
}
