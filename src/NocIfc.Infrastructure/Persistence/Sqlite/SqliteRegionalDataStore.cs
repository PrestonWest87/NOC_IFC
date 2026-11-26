using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Domain.Regional;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRegionalDataStore(SqliteConnectionFactory connections) : IRegionalDataStore
{
    public async Task<IReadOnlyDictionary<string, string?>> GetGeoJsonLayersAsync(
        IReadOnlyList<string> feedNames,
        CancellationToken cancellationToken)
    {
        if (feedNames.Count == 0)
        {
            return new Dictionary<string, string?>(StringComparer.Ordinal);
        }
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        AddFeedNameParameters(command, feedNames);
        command.CommandText = $"""
            SELECT feed_name, data
            FROM geojson_cache
            WHERE feed_name IN ({ParameterList(feedNames.Count)})
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var result = new Dictionary<string, string?>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken))
        {
            result[reader.GetString(0)] = ReadString(reader, 1);
        }
        return result;
    }

    public async Task<IReadOnlyDictionary<string, GeoJsonFeedStatus>> GetGeoJsonFeedStatusesAsync(
        IReadOnlyList<string> feedNames,
        CancellationToken cancellationToken)
    {
        if (feedNames.Count == 0)
        {
            return new Dictionary<string, GeoJsonFeedStatus>(StringComparer.Ordinal);
        }
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        AddFeedNameParameters(command, feedNames);
        command.CommandText = $"""
            SELECT feed_name, updated_at, last_attempt_at, last_success_at, last_error,
                   last_http_status, last_duration_ms, retry_after_at, feature_count, coverage_summary
            FROM geojson_cache
            WHERE feed_name IN ({ParameterList(feedNames.Count)})
            ORDER BY feed_name
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var result = new Dictionary<string, GeoJsonFeedStatus>(StringComparer.Ordinal);
        while (await reader.ReadAsync(cancellationToken))
        {
            var name = reader.GetString(0);
            result[name] = new GeoJsonFeedStatus(
                name,
                ReadDateTime(reader, 1),
                ReadDateTime(reader, 2),
                ReadDateTime(reader, 3),
                ReadString(reader, 4),
                reader.IsDBNull(5) ? null : reader.GetInt32(5),
                reader.IsDBNull(6) ? null : reader.GetInt32(6),
                ReadDateTime(reader, 7),
                reader.IsDBNull(8) ? null : reader.GetInt32(8),
                ReadString(reader, 9));
        }
        return result;
    }

    public async Task<IReadOnlyList<string>> GetActiveNwsEventTypesAsync(
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT DISTINCT hazard_type
            FROM regional_hazards
            WHERE status = 'active'
              AND (expires_at IS NULL OR julianday(expires_at) > julianday($now))
              AND (effective_at IS NULL OR julianday(effective_at) <= julianday($now))
            ORDER BY hazard_type
            """;
        command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var eventTypes = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!reader.IsDBNull(0))
            {
                eventTypes.Add(reader.GetString(0));
            }
        }
        return eventTypes;
    }

    private static void AddFeedNameParameters(SqliteCommand command, IReadOnlyList<string> feedNames)
    {
        for (var index = 0; index < feedNames.Count; index++)
        {
            command.Parameters.AddWithValue($"$feed{index}", feedNames[index]);
        }
    }

    private static string ParameterList(int count) =>
        string.Join(", ", Enumerable.Range(0, count).Select(index => $"$feed{index}"));

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
}
