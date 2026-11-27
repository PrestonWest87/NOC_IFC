using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteCrimeDataSyncStore(SqliteConnectionFactory connections)
{
    public async Task<int> SaveNewIncidentsAsync(
        IReadOnlyList<CrimeIncidentEntry> incidents,
        DateTime retentionCutoffUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var added = 0;
        foreach (var incident in incidents.GroupBy(item => item.Id, StringComparer.Ordinal).Select(group => group.First()))
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO crime_incidents (
                    id, category, raw_title, timestamp, distance_miles, severity, lat, lon, is_alert_dispatched
                ) VALUES (
                    $id, $category, $raw_title, $timestamp, $distance, $severity, $lat, $lon, 0
                )
                """;
            insert.Parameters.AddWithValue("$id", incident.Id);
            AddNullable(insert, "$category", incident.Category);
            AddNullable(insert, "$raw_title", incident.RawTitle);
            AddNullableDate(insert, "$timestamp", incident.Timestamp);
            AddNullable(insert, "$distance", incident.DistanceMiles);
            AddNullable(insert, "$severity", incident.Severity);
            AddNullable(insert, "$lat", incident.Latitude);
            AddNullable(insert, "$lon", incident.Longitude);
            added += await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var purge = connection.CreateCommand())
        {
            purge.Transaction = transaction;
            purge.CommandText = "DELETE FROM crime_incidents WHERE timestamp < $cutoff";
            purge.Parameters.AddWithValue("$cutoff", FormatDate(retentionCutoffUtc));
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return added;
    }

    public async Task<IReadOnlyList<CrimeIncidentEntry>> GetUndispatchedHighSeverityAsync(
        double maxDistanceMiles,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, category, raw_title, timestamp, distance_miles, severity, lat, lon
            FROM crime_incidents
            WHERE distance_miles <= $max_distance AND severity LIKE '%High%' AND is_alert_dispatched = 0
            ORDER BY timestamp ASC
            """;
        command.Parameters.AddWithValue("$max_distance", maxDistanceMiles);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var incidents = new List<CrimeIncidentEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            incidents.Add(new CrimeIncidentEntry(
                reader.GetString(0),
                ReadString(reader, 1),
                ReadString(reader, 2),
                ReadDateTime(reader, 3),
                reader.IsDBNull(4) ? null : reader.GetDouble(4),
                ReadString(reader, 5),
                reader.IsDBNull(6) ? null : reader.GetDouble(6),
                reader.IsDBNull(7) ? null : reader.GetDouble(7)));
        }
        return incidents;
    }

    public async Task MarkAlertDispatchedAsync(string incidentId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE crime_incidents SET is_alert_dispatched = 1 WHERE id = $id";
        command.Parameters.AddWithValue("$id", incidentId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static void AddNullableDate(SqliteCommand command, string name, DateTime? value) =>
        command.Parameters.AddWithValue(name, value is { } date ? FormatDate(date) : DBNull.Value);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
