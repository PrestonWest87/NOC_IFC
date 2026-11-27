using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteDangerZoneStore(SqliteConnectionFactory connections) : IDangerZoneStore
{
    private static readonly HashSet<string> DeleteRecordTables =
        ["keywords", "feed_sources", "users", "roles", "saved_reports"];
    private static readonly HashSet<string> ClearableTables =
        ["cloud_outages", "monitored_locations", "articles", "extracted_iocs", "feed_sources", "keywords"];

    public async Task DeleteRecordAsync(string tableName, int recordId, CancellationToken cancellationToken)
    {
        if (!DeleteRecordTables.Contains(tableName)) throw new ArgumentException("Model is not available for deletion.");
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"DELETE FROM {tableName} WHERE id = $id";
        command.Parameters.AddWithValue("$id", recordId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task ClearTablesAsync(IReadOnlyList<string> tableNames, CancellationToken cancellationToken)
    {
        var tables = tableNames.Distinct(StringComparer.Ordinal).ToArray();
        if (tables.Any(table => !ClearableTables.Contains(table)))
        {
            throw new ArgumentException("One or more tables are not available for clearing.");
        }
        if (tables.Length == 0) return;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        if (tables.Contains("monitored_locations", StringComparer.Ordinal))
        {
            await ExecuteAsync(connection, transaction,
                "DELETE FROM monitored_location_contacts", cancellationToken);
        }
        foreach (var table in tables)
        {
            await ExecuteAsync(connection, transaction, $"DELETE FROM {table}", cancellationToken);
        }
        transaction.Commit();
    }

    public Task ClearCrimeDataAsync(CancellationToken cancellationToken) =>
        ClearOneTableAsync("crime_incidents", cancellationToken);

    public async Task ClearWeatherDataAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await ExecuteAsync(connection, transaction, "DELETE FROM regional_hazards", cancellationToken);
        await ExecuteAsync(connection, transaction, "DELETE FROM geojson_cache", cancellationToken);
        await ExecuteAsync(connection, transaction,
            "UPDATE monitored_locations SET current_spc_risk = 'None'", cancellationToken);
        transaction.Commit();
    }

    public Task ClearTimelineEventsAsync(CancellationToken cancellationToken) =>
        ClearOneTableAsync("timeline_events", cancellationToken);

    public Task ClearActiveAlertsAsync(CancellationToken cancellationToken) =>
        ClearOneTableAsync("solarwinds_alerts", cancellationToken);

    public async Task RunDatabaseMaintenanceAsync(DateTime nowUtc, CancellationToken cancellationToken)
    {
        var hours12 = FormatDate(nowUtc.AddHours(-12));
        var hours24 = FormatDate(nowUtc.AddHours(-24));
        var hours48 = FormatDate(nowUtc.AddHours(-48));
        var hours72 = FormatDate(nowUtc.AddHours(-72));
        var days3 = FormatDate(nowUtc.AddDays(-3));
        var days7 = FormatDate(nowUtc.AddDays(-7));
        var days14 = FormatDate(nowUtc.AddDays(-14));
        var days30 = FormatDate(nowUtc.AddDays(-30));
        var days60 = FormatDate(nowUtc.AddDays(-60));
        var days90 = FormatDate(nowUtc.AddDays(-90));
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await ExecuteAsync(connection, transaction,
            "DELETE FROM articles WHERE score < 50 AND published_date < $cutoff AND COALESCE(is_pinned, 0) = 0",
            cancellationToken, ("$cutoff", days3));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM articles WHERE published_date < $cutoff AND COALESCE(is_pinned, 0) = 0",
            cancellationToken, ("$cutoff", days30));
        await ExecuteAsync(connection, transaction, "DELETE FROM solarwinds_alerts WHERE received_at < $cutoff",
            cancellationToken, ("$cutoff", days60));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM regional_hazards WHERE status != 'active' AND updated_at < $cutoff",
            cancellationToken, ("$cutoff", hours48));
        await ExecuteAsync(connection, transaction, "DELETE FROM regional_outages WHERE detected_at < $cutoff",
            cancellationToken, ("$cutoff", hours12));
        await ExecuteAsync(connection, transaction, "DELETE FROM bgp_anomalies WHERE detected_at < $cutoff",
            cancellationToken, ("$cutoff", hours12));
        await ExecuteAsync(connection, transaction, "DELETE FROM cve_items WHERE date_added < $cutoff",
            cancellationToken, ("$cutoff", days7));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM cloud_outages WHERE is_resolved = 1 AND updated_at < $cutoff",
            cancellationToken, ("$cutoff", hours24));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM cloud_outages WHERE is_resolved = 0 AND updated_at < $cutoff",
            cancellationToken, ("$cutoff", days14));
        await ExecuteAsync(connection, transaction, "DELETE FROM crime_incidents WHERE timestamp < $cutoff",
            cancellationToken, ("$cutoff", days7));
        await ExecuteAsync(connection, transaction, "DELETE FROM internal_risk_snapshots WHERE timestamp < $cutoff",
            cancellationToken, ("$cutoff", days90));
        await ExecuteAsync(connection, transaction, "DELETE FROM timeline_events WHERE timestamp < $cutoff",
            cancellationToken, ("$cutoff", days90));
        await ExecuteAsync(connection, transaction, "DELETE FROM elastic_events WHERE timestamp < $cutoff",
            cancellationToken, ("$cutoff", hours72));
        await ExecuteAsync(connection, transaction, "DELETE FROM failed_login_attempts WHERE attempted_at < $cutoff",
            cancellationToken, ("$cutoff", hours24));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM password_reset_tokens WHERE (expires_at < $now OR used_at IS NOT NULL) AND created_at < $cutoff",
            cancellationToken, ("$now", FormatDate(nowUtc)), ("$cutoff", days30));
        await ExecuteAsync(connection, transaction,
            "UPDATE password_reset_requests SET status = 'expired' WHERE status = 'pending_review' AND requested_at < $cutoff",
            cancellationToken, ("$cutoff", days30));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM password_reset_requests WHERE status IN ('unmatched', 'denied', 'completed', 'expired') AND requested_at < $cutoff",
            cancellationToken, ("$cutoff", days90));
        await ExecuteAsync(connection, transaction,
            "UPDATE email_change_requests SET status = 'expired' WHERE status = 'pending_verification' AND verification_expires_at < $now",
            cancellationToken, ("$now", FormatDate(nowUtc)));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM email_change_requests WHERE status IN ('denied', 'completed', 'expired', 'conflict') AND requested_at < $cutoff",
            cancellationToken, ("$cutoff", days90));
        await ExecuteAsync(connection, transaction,
            "DELETE FROM extracted_iocs WHERE article_id NOT IN (SELECT id FROM articles)",
            cancellationToken);
        transaction.Commit();
        await using var optimize = connection.CreateCommand();
        optimize.CommandText = "PRAGMA optimize; PRAGMA wal_checkpoint(PASSIVE);";
        await optimize.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task ClearOneTableAsync(string tableName, CancellationToken cancellationToken)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal)
            { "crime_incidents", "timeline_events", "solarwinds_alerts" };
        if (!allowed.Contains(tableName)) throw new ArgumentException("Table is not available for clearing.");
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"DELETE FROM {tableName}";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
