using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteDangerZoneStoreTests
{
    [Fact]
    public async Task ClearsOnlyNamedAllowlistedTablesAndRelatedSiteContacts()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-danger-zone-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE monitored_locations (id INTEGER PRIMARY KEY, current_spc_risk TEXT);
                    CREATE TABLE monitored_location_contacts (id INTEGER PRIMARY KEY, monitored_location_id INTEGER);
                    CREATE TABLE articles (id INTEGER PRIMARY KEY);
                    CREATE TABLE extracted_iocs (id INTEGER PRIMARY KEY);
                    CREATE TABLE feed_sources (id INTEGER PRIMARY KEY);
                    CREATE TABLE keywords (id INTEGER PRIMARY KEY);
                    CREATE TABLE cloud_outages (id INTEGER PRIMARY KEY);
                    CREATE TABLE crime_incidents (id INTEGER PRIMARY KEY);
                    CREATE TABLE regional_hazards (id INTEGER PRIMARY KEY);
                    CREATE TABLE geojson_cache (feed_name TEXT PRIMARY KEY);
                    CREATE TABLE timeline_events (id INTEGER PRIMARY KEY);
                    CREATE TABLE solarwinds_alerts (id INTEGER PRIMARY KEY);
                    INSERT INTO monitored_locations VALUES (1, 'High');
                    INSERT INTO monitored_location_contacts VALUES (1, 1);
                    INSERT INTO articles VALUES (1);
                    INSERT INTO extracted_iocs VALUES (1);
                    INSERT INTO feed_sources VALUES (1);
                    INSERT INTO keywords VALUES (1);
                    INSERT INTO cloud_outages VALUES (1);
                    INSERT INTO crime_incidents VALUES (1);
                    INSERT INTO regional_hazards VALUES (1);
                    INSERT INTO geojson_cache VALUES ('weather');
                    INSERT INTO timeline_events VALUES (1);
                    INSERT INTO solarwinds_alerts VALUES (1);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var commands = new DangerZoneCommands(new SqliteDangerZoneStore(connections));
            await commands.ClearTablesAsync(["MonitoredLocation", "Article", "NotAllowed"], CancellationToken.None);
            Assert.Equal(0, await CountAsync(connections, "monitored_locations"));
            Assert.Equal(0, await CountAsync(connections, "monitored_location_contacts"));
            Assert.Equal(0, await CountAsync(connections, "articles"));
            Assert.Equal(1, await CountAsync(connections, "extracted_iocs"));
            Assert.Equal(1, await CountAsync(connections, "cloud_outages"));
            await commands.DeleteRecordAsync("Keyword", 1, CancellationToken.None);
            Assert.Equal(0, await CountAsync(connections, "keywords"));
            await Assert.ThrowsAsync<ArgumentException>(
                () => commands.DeleteRecordAsync("NotAllowed", 1, CancellationToken.None));

            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var seed = connection.CreateCommand();
                seed.CommandText = "INSERT INTO monitored_locations VALUES (2, 'High')";
                await seed.ExecuteNonQueryAsync();
            }
            await commands.ClearWeatherDataAsync(CancellationToken.None);
            Assert.Equal(0, await CountAsync(connections, "regional_hazards"));
            Assert.Equal(0, await CountAsync(connections, "geojson_cache"));
            Assert.Equal("None", await ScalarAsync(connections,
                "SELECT current_spc_risk FROM monitored_locations WHERE id = 2"));
            await commands.ClearCrimeDataAsync(CancellationToken.None);
            await commands.ClearTimelineEventsAsync(CancellationToken.None);
            await commands.ClearActiveAlertsAsync(CancellationToken.None);
            Assert.Equal(0, await CountAsync(connections, "crime_incidents"));
            Assert.Equal(0, await CountAsync(connections, "timeline_events"));
            Assert.Equal(0, await CountAsync(connections, "solarwinds_alerts"));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task MaintenancePrunesOldRowsAndExpiresReviewCredentials()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-maintenance-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE articles (id INTEGER PRIMARY KEY, score REAL, published_date DATETIME, is_pinned INTEGER);
                    CREATE TABLE solarwinds_alerts (id INTEGER PRIMARY KEY, received_at DATETIME);
                    CREATE TABLE regional_hazards (id INTEGER PRIMARY KEY, status TEXT, updated_at DATETIME);
                    CREATE TABLE regional_outages (id INTEGER PRIMARY KEY, detected_at DATETIME);
                    CREATE TABLE bgp_anomalies (id INTEGER PRIMARY KEY, detected_at DATETIME);
                    CREATE TABLE cve_items (id INTEGER PRIMARY KEY, date_added DATETIME);
                    CREATE TABLE cloud_outages (id INTEGER PRIMARY KEY, is_resolved INTEGER, updated_at DATETIME);
                    CREATE TABLE crime_incidents (id INTEGER PRIMARY KEY, timestamp DATETIME);
                    CREATE TABLE internal_risk_snapshots (id INTEGER PRIMARY KEY, timestamp DATETIME);
                    CREATE TABLE timeline_events (id INTEGER PRIMARY KEY, timestamp DATETIME);
                    CREATE TABLE elastic_events (id INTEGER PRIMARY KEY, timestamp DATETIME);
                    CREATE TABLE failed_login_attempts (id INTEGER PRIMARY KEY, attempted_at DATETIME);
                    CREATE TABLE password_reset_tokens (id INTEGER PRIMARY KEY, expires_at DATETIME, used_at DATETIME, created_at DATETIME);
                    CREATE TABLE password_reset_requests (id INTEGER PRIMARY KEY, status TEXT, requested_at DATETIME);
                    CREATE TABLE email_change_requests (id INTEGER PRIMARY KEY, status TEXT, verification_expires_at DATETIME, requested_at DATETIME);
                    CREATE TABLE extracted_iocs (id INTEGER PRIMARY KEY, article_id INTEGER);
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var seed = connection.CreateCommand();
                seed.CommandText = """
                    INSERT INTO articles VALUES (1, 10, '2026-01-01 00:00:00', 0);
                    INSERT INTO articles VALUES (2, 90, '2026-01-01 00:00:00', 1);
                    INSERT INTO articles VALUES (3, 90, '2026-11-27 00:00:00', 0);
                    INSERT INTO password_reset_requests VALUES (1, 'pending_review', '2026-10-01 00:00:00');
                    INSERT INTO password_reset_requests VALUES (2, 'completed', '2026-08-01 00:00:00');
                    INSERT INTO email_change_requests VALUES (1, 'pending_verification', NULL, '2026-11-01 00:00:00');
                    INSERT INTO extracted_iocs VALUES (1, 999);
                    """;
                await seed.ExecuteNonQueryAsync();
            }

            await new SqliteDangerZoneStore(connections).RunDatabaseMaintenanceAsync(
                new DateTime(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc), CancellationToken.None);

            Assert.Equal(2, await CountAsync(connections, "articles"));
            Assert.Equal("expired", await ScalarAsync(connections, "SELECT status FROM password_reset_requests WHERE id = 1"));
            Assert.Equal(0, await CountAsync(connections, "password_reset_requests WHERE status = 'completed'"));
            Assert.Equal(0, await CountAsync(connections, "extracted_iocs"));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static async Task<int> CountAsync(SqliteConnectionFactory connections, string tableOrClause)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM {tableOrClause}";
        return Convert.ToInt32(await command.ExecuteScalarAsync(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static async Task<string?> ScalarAsync(SqliteConnectionFactory connections, string query)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = query;
        return (string?)await command.ExecuteScalarAsync();
    }
}
