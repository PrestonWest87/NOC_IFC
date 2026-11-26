using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Domain.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAiopsDashboardStore(SqliteConnectionFactory connections) : IAiopsDashboardStore
{
    public async Task<IReadOnlyList<AiopsAlertEntry>> GetUnresolvedAlertsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken)
    {
        if (allowedSiteNames is { Count: 0 }) return [];
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var scope = AddSiteFilter(command, allowedSiteNames, "mapped_location");
        command.CommandText = $"""
            SELECT id, event_type, severity, node_name, ip_address, status, sw_timestamp, details,
                   node_link, raw_payload, mapped_location, received_at, resolved_at, is_dispatched,
                   is_ticketed, is_correlated, needs_dispatch, ai_root_cause, device_type, event_category,
                   acknowledged_by, acknowledged_at, dispatched_by, dispatched_at, onpage_sent_at
            FROM solarwinds_alerts
            WHERE status != 'Resolved' AND is_correlated = 0 {scope}
            ORDER BY id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var alerts = new List<AiopsAlertEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            alerts.Add(new AiopsAlertEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3),
                ReadString(reader, 4), ReadString(reader, 5), ReadString(reader, 6), ReadString(reader, 7),
                ReadString(reader, 8), ReadString(reader, 9), ReadString(reader, 10), ReadDateTime(reader, 11),
                ReadDateTime(reader, 12), ReadBoolean(reader, 13), ReadBoolean(reader, 14), ReadBoolean(reader, 15),
                ReadBoolean(reader, 16), ReadString(reader, 17), ReadString(reader, 18), ReadString(reader, 19),
                ReadString(reader, 20), ReadDateTime(reader, 21), ReadString(reader, 22),
                ReadDateTime(reader, 23), ReadDateTime(reader, 24)));
        }
        return alerts;
    }

    public async Task<IReadOnlyList<AiopsTimelineEventEntry>> GetTimelineEventsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        int limit,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 500) throw new ArgumentOutOfRangeException(nameof(limit));
        if (allowedSiteNames is { Count: 0 }) return [];
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var scope = AddSiteFilter(command, allowedSiteNames, "site_name");
        command.CommandText = $"""
            SELECT id, timestamp, source, event_type, message, site_name
            FROM timeline_events
            WHERE 1 = 1 {scope}
            ORDER BY timestamp DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var events = new List<AiopsTimelineEventEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            events.Add(new AiopsTimelineEventEntry(
                reader.GetInt32(0), ReadDateTime(reader, 1), ReadString(reader, 2), ReadString(reader, 3),
                SanitizeText(ReadString(reader, 4)), ReadString(reader, 5)));
        }
        return events;
    }

    public async Task<IReadOnlyList<AiopsRegionalOutageEntry>> GetUnresolvedOutagesAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, outage_type, provider, description, affected_area, lat, lon, radius_km, detected_at, is_resolved
            FROM regional_outages
            WHERE is_resolved = 0
            ORDER BY detected_at DESC
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var outages = new List<AiopsRegionalOutageEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            outages.Add(new AiopsRegionalOutageEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3),
                ReadString(reader, 4), ReadNullableDouble(reader, 5), ReadNullableDouble(reader, 6),
                reader.IsDBNull(7) ? 10 : reader.GetDouble(7), ReadDateTime(reader, 8), ReadBoolean(reader, 9)));
        }
        return outages;
    }

    public async Task<IReadOnlyDictionary<string, int>> GetActiveIssueCountsAsync(
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken)
    {
        if (allowedSiteNames is { Count: 0 }) return new Dictionary<string, int>(StringComparer.Ordinal);
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var scope = AddSiteFilter(command, allowedSiteNames, "mapped_location");
        command.CommandText = $"""
            SELECT mapped_location, COUNT(id)
            FROM solarwinds_alerts
            WHERE status != 'Resolved' AND mapped_location IS NOT NULL {scope}
            GROUP BY mapped_location
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!reader.IsDBNull(0)) result[reader.GetString(0)] = reader.GetInt32(1);
        }
        return result;
    }

    public async Task<bool> AcknowledgeAlertsAsync(
        IReadOnlyList<int> alertIds,
        string username,
        DateTime acknowledgedAtUtc,
        IReadOnlySet<string>? allowedSiteNames,
        CancellationToken cancellationToken)
    {
        var ids = alertIds.Where(id => id > 0).Distinct().ToArray();
        if (ids.Length == 0) return true;

        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var existing = new List<(int Id, string? SiteName)>();
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = "SELECT mapped_location FROM solarwinds_alerts WHERE id = $id";
            var idParameter = select.Parameters.Add("$id", SqliteType.Integer);
            foreach (var id in ids)
            {
                idParameter.Value = id;
                var mappedLocation = await select.ExecuteScalarAsync(cancellationToken);
                if (allowedSiteNames is not null
                    && (mappedLocation is not string siteName || !allowedSiteNames.Contains(siteName)))
                {
                    transaction.Rollback();
                    return false;
                }
                if (mappedLocation is not null)
                {
                    existing.Add((id, mappedLocation is string name ? name : null));
                }
            }
        }

        var timestamp = FormatDate(acknowledgedAtUtc);
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE solarwinds_alerts
                SET is_correlated = 1, needs_dispatch = 0, acknowledged_by = $username, acknowledged_at = $now
                WHERE id = $id
                """;
            var idParameter = update.Parameters.Add("$id", SqliteType.Integer);
            update.Parameters.AddWithValue("$username", username);
            update.Parameters.AddWithValue("$now", timestamp);
            foreach (var alert in existing)
            {
                idParameter.Value = alert.Id;
                await update.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        await using (var updateLocation = connection.CreateCommand())
        {
            updateLocation.Transaction = transaction;
            updateLocation.CommandText = """
                UPDATE monitored_locations
                SET status_modified_by = $username, status_modified_at = $now
                WHERE id = (SELECT id FROM monitored_locations WHERE name = $site LIMIT 1)
                """;
            updateLocation.Parameters.AddWithValue("$username", username);
            updateLocation.Parameters.AddWithValue("$now", timestamp);
            var siteParameter = updateLocation.Parameters.Add("$site", SqliteType.Text);
            foreach (var site in existing.Select(alert => alert.SiteName).Where(site => !string.IsNullOrEmpty(site)).Distinct(StringComparer.Ordinal))
            {
                siteParameter.Value = site!;
                await updateLocation.ExecuteNonQueryAsync(cancellationToken);
            }
        }

        transaction.Commit();
        return true;
    }

    private static string AddSiteFilter(SqliteCommand command, IReadOnlySet<string>? allowedSiteNames, string column)
    {
        if (allowedSiteNames is null) return "";
        var names = allowedSiteNames.OrderBy(name => name, StringComparer.Ordinal).ToArray();
        for (var index = 0; index < names.Length; index++)
        {
            command.Parameters.AddWithValue($"$site{index}", names[index]);
        }
        return $"AND {column} IN ({string.Join(", ", Enumerable.Range(0, names.Length).Select(index => $"$site{index}"))})";
    }

    private static string SanitizeText(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var result = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.Value <= 0xffff && rune.Value != '?') result.Append(rune.ToString());
        }
        return result.ToString().Trim();
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static bool ReadBoolean(SqliteDataReader reader, int ordinal) =>
        !reader.IsDBNull(ordinal) && (reader.GetValue(ordinal) is long integer ? integer != 0 : reader.GetBoolean(ordinal));

    private static double? ReadNullableDouble(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetDouble(ordinal);
}
