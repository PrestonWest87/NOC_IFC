using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteOperationalDashboardStore(SqliteConnectionFactory connections) : IOperationalDashboardStore
{
    public async Task<DashboardMetrics> GetMetricsAsync(
        DateTime sinceUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT
                (SELECT COUNT(*) FROM articles WHERE published_date >= $since AND score >= 50),
                (SELECT COUNT(*) FROM cve_items WHERE date_added >= $since),
                (SELECT COUNT(*) FROM regional_hazards
                    WHERE updated_at >= $since AND status = 'active'
                      AND (expires_at IS NULL OR expires_at > $now)
                      AND (effective_at IS NULL OR effective_at <= $now)),
                (SELECT COUNT(*) FROM cloud_outages WHERE updated_at >= $since AND is_resolved = 0)
            """;
        command.Parameters.AddWithValue("$since", FormatDate(sinceUtc));
        command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new DashboardMetrics(0, 0, 0, 0);
        }
        return new DashboardMetrics(
            reader.GetInt32(0), reader.GetInt32(1), reader.GetInt32(2), reader.GetInt32(3));
    }

    public async Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(
        DateTime nowUtc,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, hazard_id, hazard_type, severity, title, description, location,
                   updated_at, last_seen_at, status, sent_at, effective_at, onset_at,
                   expires_at, event_ending_at, message_type, references_json,
                   coverage_scope, coverage_precision
            FROM regional_hazards
            WHERE status = 'active'
              AND (expires_at IS NULL OR expires_at > $now)
              AND (effective_at IS NULL OR effective_at <= $now)
            ORDER BY updated_at DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
        command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var hazards = new List<DashboardRegionalHazard>();
        while (await reader.ReadAsync(cancellationToken))
        {
            hazards.Add(new DashboardRegionalHazard(
                reader.GetInt32(0),
                ReadString(reader, 1),
                ReadString(reader, 2),
                ReadString(reader, 3),
                ReadString(reader, 4),
                ReadString(reader, 5),
                ReadString(reader, 6),
                ReadDateTime(reader, 7),
                ReadDateTime(reader, 8),
                reader.IsDBNull(9) ? "unknown" : reader.GetString(9),
                ReadDateTime(reader, 10),
                ReadDateTime(reader, 11),
                ReadDateTime(reader, 12),
                ReadDateTime(reader, 13),
                ReadDateTime(reader, 14),
                ReadString(reader, 15),
                ReadJson(reader, 16),
                ReadString(reader, 17),
                ReadString(reader, 18)));
        }
        return hazards;
    }

    public async Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, record_date, cyber_points, physical_points, cyber_baseline, physical_baseline
            FROM daily_threat_scores
            WHERE record_date >= $since
            ORDER BY record_date ASC
            """;
        command.Parameters.AddWithValue("$since", FormatDate(sinceUtc));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var points = new List<DailyThreatScoreEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            points.Add(new DailyThreatScoreEntry(
                reader.GetInt32(0),
                ReadDateTime(reader, 1),
                reader.IsDBNull(2) ? null : reader.GetDouble(2),
                reader.IsDBNull(3) ? null : reader.GetDouble(3),
                reader.IsDBNull(4) ? null : reader.GetDouble(4),
                reader.IsDBNull(5) ? null : reader.GetDouble(5)));
        }
        return points;
    }

    public async Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rolling_summary, rolling_summary_time,
                   global_brief, global_brief_time,
                   internal_brief, internal_brief_time,
                   unified_brief, unified_brief_time,
                   last_global_risk, last_internal_risk
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        return new DashboardBriefSnapshot(
            ReadString(reader, 0),
            ReadDateTime(reader, 1),
            ReadString(reader, 2),
            ReadDateTime(reader, 3),
            ReadString(reader, 4),
            ReadDateTime(reader, 5),
            ReadString(reader, 6),
            ReadDateTime(reader, 7),
            ReadString(reader, 8),
            ReadString(reader, 9));
    }

    public async Task<bool> SaveUnifiedBriefAsync(
        string content,
        DateTime savedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE system_config SET unified_brief = $brief, unified_brief_time = $saved_at WHERE id = (SELECT id FROM system_config ORDER BY id LIMIT 1)";
        command.Parameters.AddWithValue("$brief", content);
        command.Parameters.AddWithValue("$saved_at", FormatDate(savedAtUtc));
        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

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

    private static JsonElement? ReadJson(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        using var document = JsonDocument.Parse(reader.GetString(ordinal));
        return document.RootElement.Clone();
    }
}
