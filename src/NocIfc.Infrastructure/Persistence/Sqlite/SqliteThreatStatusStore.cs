using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteThreatStatusStore(SqliteConnectionFactory connections) : IThreatStatusStore
{
    public async Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(
        bool activeOnly,
        DateTime updatedAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var activeFilter = activeOnly ? " AND is_resolved = 0" : "";
        command.CommandText = $"""
            SELECT id, provider, service, title, description, link, is_resolved,
                   updated_at, external_id, status_code
            FROM cloud_outages
            WHERE updated_at >= $updated_after{activeFilter}
            ORDER BY updated_at DESC
            """;
        command.Parameters.AddWithValue("$updated_after", FormatDate(updatedAfterUtc));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var outages = new List<CloudOutageEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            outages.Add(ReadCloudOutage(reader));
        }
        return outages;
    }

    public async Task<IReadOnlyList<CrimeIncidentEntry>> GetRecentCrimesAsync(
        double maxDistance,
        DateTime occurredAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, category, raw_title, timestamp, distance_miles, severity, lat, lon
            FROM crime_incidents
            WHERE timestamp >= $occurred_after AND distance_miles <= $max_distance
            ORDER BY timestamp DESC
            """;
        command.Parameters.AddWithValue("$occurred_after", FormatDate(occurredAfterUtc));
        command.Parameters.AddWithValue("$max_distance", maxDistance);
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

    public async Task<Microsoft365StatusSnapshot> GetMicrosoft365StatusAsync(
        DateTime updatedAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        Microsoft365FeedState? feedState = null;
        await using (var stateCommand = connection.CreateCommand())
        {
            stateCommand.CommandText = """
                SELECT last_attempt_at, last_success_at, last_duration_ms, last_http_status, last_error
                FROM microsoft_365_status_state
                WHERE id = 1
                LIMIT 1
                """;
            await using var reader = await stateCommand.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                feedState = new Microsoft365FeedState(
                    ReadDateTime(reader, 0),
                    ReadDateTime(reader, 1),
                    reader.IsDBNull(2) ? null : reader.GetInt32(2),
                    reader.IsDBNull(3) ? null : reader.GetInt32(3),
                    ReadString(reader, 4));
            }
        }

        bool? jobEnabled = null;
        int? jobInterval = null;
        await using (var jobCommand = connection.CreateCommand())
        {
            jobCommand.CommandText = "SELECT enabled, every_value FROM scheduler_job_config WHERE job_key = 'cloud_outages' LIMIT 1";
            await using var reader = await jobCommand.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                jobEnabled = reader.IsDBNull(0) ? null : reader.GetBoolean(0);
                jobInterval = reader.IsDBNull(1) ? null : reader.GetInt32(1);
            }
        }

        var incidents = new List<CloudOutageEntry>();
        await using (var incidentCommand = connection.CreateCommand())
        {
            incidentCommand.CommandText = """
                SELECT id, provider, service, title, description, link, is_resolved,
                       updated_at, external_id, status_code
                FROM cloud_outages
                WHERE provider = 'Microsoft 365' AND is_resolved = 0
                  AND updated_at >= $updated_after
                ORDER BY updated_at DESC
                LIMIT 100
                """;
            incidentCommand.Parameters.AddWithValue("$updated_after", FormatDate(updatedAfterUtc));
            await using var reader = await incidentCommand.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                incidents.Add(ReadCloudOutage(reader));
            }
        }
        return new Microsoft365StatusSnapshot(feedState, jobEnabled, jobInterval, incidents);
    }

    private static CloudOutageEntry ReadCloudOutage(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        ReadString(reader, 1),
        ReadString(reader, 2),
        ReadString(reader, 3),
        ReadString(reader, 4),
        ReadString(reader, 5),
        reader.IsDBNull(6) ? null : reader.GetBoolean(6),
        ReadDateTime(reader, 7),
        ReadString(reader, 8),
        ReadString(reader, 9));

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
