using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteMaintenanceExpiryStore(SqliteConnectionFactory connections) : IMaintenanceExpiryStore
{
    public async Task<IReadOnlyList<string>> ClearExpiredAsync(
        DateOnly centralToday,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var cleared = new List<string>();
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT name
                FROM monitored_locations
                WHERE under_maintenance = 1
                  AND maintenance_etr IS NOT NULL
                  AND date(maintenance_etr) < $today
                """;
            select.Parameters.AddWithValue("$today", centralToday.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (!reader.IsDBNull(0)) cleared.Add(reader.GetString(0));
            }
        }
        if (cleared.Count > 0)
        {
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE monitored_locations
                SET under_maintenance = 0,
                    maintenance_etr = NULL,
                    maintenance_reason = NULL,
                    status_modified_by = 'System (ETR Expired)',
                    status_modified_at = $now
                WHERE under_maintenance = 1
                  AND maintenance_etr IS NOT NULL
                  AND date(maintenance_etr) < $today
                """;
            update.Parameters.AddWithValue("$today", centralToday.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
            update.Parameters.AddWithValue("$now", nowUtc.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return cleared;
    }
}
