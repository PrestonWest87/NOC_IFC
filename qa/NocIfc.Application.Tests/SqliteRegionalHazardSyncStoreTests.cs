using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRegionalHazardSyncStoreTests
{
    [Fact]
    public async Task NwsLeaseSerializesPollsAndHonorsRetryAfter()
    {
        var (path, connections) = await CreateDatabaseAsync();
        try
        {
            var store = new SqliteRegionalHazardSyncStore(connections);
            var now = TruncateToSqlitePrecision(DateTime.UtcNow);

            var first = await store.ReserveNwsPollAsync(now, CancellationToken.None);
            var duplicate = await store.ReserveNwsPollAsync(now.AddSeconds(10), CancellationToken.None);

            Assert.Equal("reserved", first.Status);
            Assert.Equal("throttled", duplicate.Status);
            Assert.Equal(now, duplicate.LastAttemptAt);

            var retryAt = now.AddMinutes(2);
            await store.RecordNwsFailureAsync(now.AddSeconds(10), 429, 17, "rate limited", retryAt, CancellationToken.None);
            var backedOff = await store.ReserveNwsPollAsync(now.AddSeconds(30), CancellationToken.None);
            var afterBackoff = await store.ReserveNwsPollAsync(now.AddMinutes(3), CancellationToken.None);

            Assert.Equal("backoff", backedOff.Status);
            Assert.Equal(retryAt, backedOff.RetryAfterAt);
            Assert.Equal("reserved", afterBackoff.Status);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task SnapshotUpsertsLifecycleRowsAndFailuresKeepLastGoodPayload()
    {
        var (path, connections) = await CreateDatabaseAsync();
        try
        {
            var store = new SqliteRegionalHazardSyncStore(connections);
            var now = TruncateToSqlitePrecision(DateTime.UtcNow);
            var oldAlert = Hazard("https://api.weather.gov/alerts/old-alert", "Old Warning");
            var absentAlert = Hazard("https://api.weather.gov/alerts/absent-alert", "Absent Warning");
            var firstSource = "{\"type\":\"FeatureCollection\",\"features\":[1,2]}";
            await store.SaveNwsSnapshotAsync(
                firstSource, Collection(), Collection(), "{}", 2, 0, 0, "\"etag-1\"", null,
                now, 15, [oldAlert, absentAlert], [], CancellationToken.None);

            var secondSource = "{\"type\":\"FeatureCollection\",\"features\":[3]}";
            await store.SaveNwsSnapshotAsync(
                secondSource, Collection(), Collection(), "{}", 1, 0, 0, "\"etag-2\"", null,
                now.AddMinutes(1), 21, [Hazard("https://api.weather.gov/alerts/new-alert", "New Warning")],
                [new RegionalCapReference("old-alert", "superseded")], CancellationToken.None);
            await store.RecordNwsFailureAsync(now.AddMinutes(2), 503, 10, "temporary failure", null, CancellationToken.None);

            var statuses = await ReadHazardStatusesAsync(connections);
            var cache = await ReadNwsCacheAsync(connections);
            Assert.Equal("superseded", statuses["https://api.weather.gov/alerts/old-alert"]);
            Assert.Equal("inactive", statuses["https://api.weather.gov/alerts/absent-alert"]);
            Assert.Equal("active", statuses["https://api.weather.gov/alerts/new-alert"]);
            Assert.Equal(secondSource, cache.Data);
            Assert.Equal(now.AddMinutes(1), cache.LastSuccessAt);
            Assert.Equal("temporary failure", cache.LastError);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static RegionalHazardSyncRow Hazard(string id, string title) => new(
        id, "Tornado Warning", "Extreme", title, "Details", "County", null, null, null,
        DateTime.UtcNow.AddHours(1), null, "Alert", "[]", "arkansas", "alert_geometry", "active");

    private static string Collection() => "{\"type\":\"FeatureCollection\",\"features\":[]}";

    private static DateTime TruncateToSqlitePrecision(DateTime value) =>
        DateTime.ParseExact(value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture),
            "yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture, DateTimeStyles.None);

    private static async Task<(string Path, SqliteConnectionFactory Connections)> CreateDatabaseAsync()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-regional-sync-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{path}");
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE geojson_cache (
                feed_name TEXT PRIMARY KEY, data TEXT, updated_at DATETIME,
                last_attempt_at DATETIME, last_success_at DATETIME, last_error TEXT,
                last_http_status INTEGER, last_duration_ms INTEGER, retry_after_at DATETIME,
                etag TEXT, last_modified TEXT, feature_count INTEGER, coverage_summary TEXT
            );
            CREATE TABLE regional_hazards (
                id INTEGER PRIMARY KEY, hazard_id TEXT UNIQUE, hazard_type TEXT, severity TEXT,
                title TEXT, description TEXT, location TEXT, updated_at DATETIME, last_seen_at DATETIME,
                status TEXT, sent_at DATETIME, effective_at DATETIME, onset_at DATETIME,
                expires_at DATETIME, event_ending_at DATETIME, message_type TEXT,
                references_json TEXT, coverage_scope TEXT, coverage_precision TEXT
            );
            CREATE TABLE system_config (
                id INTEGER PRIMARY KEY, alerted_eq_ids TEXT, alerted_wildfire_ids TEXT,
                wildfire_proximity_state TEXT
            );
            INSERT INTO system_config VALUES (1, '[]', '[]', '{}');
            """;
        await command.ExecuteNonQueryAsync();
        return (path, connections);
    }

    private static async Task<Dictionary<string, string>> ReadHazardStatusesAsync(SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT hazard_id, status FROM regional_hazards";
        await using var reader = await command.ExecuteReaderAsync();
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        while (await reader.ReadAsync()) result[reader.GetString(0)] = reader.GetString(1);
        return result;
    }

    private static async Task<(string? Data, DateTime? LastSuccessAt, string? LastError)> ReadNwsCacheAsync(
        SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT data, last_success_at, last_error FROM geojson_cache WHERE feed_name = 'nws_region'";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        return (
            reader.IsDBNull(0) ? null : reader.GetString(0),
            reader.IsDBNull(1) ? null : DateTime.SpecifyKind(reader.GetDateTime(1), DateTimeKind.Unspecified),
            reader.IsDBNull(2) ? null : reader.GetString(2));
    }
}
