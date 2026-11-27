namespace NocIfc.Application.Abstractions.Settings;

public interface IDangerZoneStore
{
    Task DeleteRecordAsync(string tableName, int recordId, CancellationToken cancellationToken);
    Task ClearTablesAsync(IReadOnlyList<string> tableNames, CancellationToken cancellationToken);
    Task ClearCrimeDataAsync(CancellationToken cancellationToken);
    Task ClearWeatherDataAsync(CancellationToken cancellationToken);
    Task ClearTimelineEventsAsync(CancellationToken cancellationToken);
    Task ClearActiveAlertsAsync(CancellationToken cancellationToken);
    Task RunDatabaseMaintenanceAsync(DateTime nowUtc, CancellationToken cancellationToken);
}
