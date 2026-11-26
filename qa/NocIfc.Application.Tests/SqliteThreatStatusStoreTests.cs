using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteThreatStatusStoreTests
{
    [Fact]
    public async Task FiltersAndOrdersCloudCrimeAndMicrosoftFeedStateRows()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-threat-status-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            var now = DateTime.UtcNow;
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE cloud_outages (
                        id INTEGER PRIMARY KEY, provider TEXT, service TEXT, title TEXT,
                        description TEXT, link TEXT, is_resolved INTEGER, updated_at DATETIME,
                        external_id TEXT, status_code TEXT
                    );
                    CREATE TABLE crime_incidents (
                        id TEXT PRIMARY KEY, category TEXT, raw_title TEXT, timestamp DATETIME,
                        distance_miles REAL, severity TEXT, lat REAL, lon REAL, is_alert_dispatched INTEGER
                    );
                    CREATE TABLE microsoft_365_status_state (
                        id INTEGER PRIMARY KEY, last_attempt_at DATETIME, last_success_at DATETIME,
                        last_duration_ms INTEGER, last_http_status INTEGER, last_error TEXT
                    );
                    CREATE TABLE scheduler_job_config (job_key TEXT PRIMARY KEY, enabled INTEGER, every_value INTEGER);
                    """;
                await setup.ExecuteNonQueryAsync();
                await InsertCloudOutageAsync(connection, 1, "Azure", "Recent", false, now.AddDays(-2));
                await InsertCloudOutageAsync(connection, 2, "Azure", "Resolved", true, now.AddDays(-3));
                await InsertCloudOutageAsync(connection, 3, "Azure", "Old", false, now.AddDays(-10));
                await InsertCloudOutageAsync(connection, 4, "Microsoft 365", "Outlook issue", false, now.AddHours(-1), "ServiceDegradation");
                await InsertCloudOutageAsync(connection, 5, "Microsoft 365", "Teams issue", false, now.AddHours(-2), "Investigating");
                await using var auxiliary = connection.CreateCommand();
                auxiliary.CommandText = """
                    INSERT INTO microsoft_365_status_state VALUES (1, $attempt, $success, 350, 200, NULL);
                    INSERT INTO scheduler_job_config VALUES ('cloud_outages', 1, 10);
                    INSERT INTO crime_incidents VALUES
                        ('near', 'Theft', 'Copper theft', $near, 0.4, 'High', 34.7, -92.3, 0),
                        ('far', 'Theft', 'Other', $near, 0.9, 'Low', 34.8, -92.4, 0),
                        ('old-crime', 'Theft', 'Old incident', $old, 0.2, 'Low', 34.9, -92.5, 0);
                    """;
                auxiliary.Parameters.AddWithValue("$attempt", FormatDate(now.AddMinutes(-1)));
                auxiliary.Parameters.AddWithValue("$success", FormatDate(now.AddMinutes(-2)));
                auxiliary.Parameters.AddWithValue("$near", FormatDate(now.AddHours(-1)));
                auxiliary.Parameters.AddWithValue("$old", FormatDate(now.AddHours(-30)));
                await auxiliary.ExecuteNonQueryAsync();
            }

            var store = new SqliteThreatStatusStore(connections);
            var active = await store.GetCloudOutagesAsync(true, now.AddDays(-7), CancellationToken.None);
            Assert.Equal(new[] { 4, 5, 1 }, active.Select(outage => outage.Id));
            var allRecent = await store.GetCloudOutagesAsync(false, now.AddDays(-7), CancellationToken.None);
            Assert.Equal(new[] { 4, 5, 1, 2 }, allRecent.Select(outage => outage.Id));

            var crimes = await store.GetRecentCrimesAsync(0.6, now.AddHours(-24), CancellationToken.None);
            Assert.Single(crimes);
            Assert.Equal("near", crimes[0].Id);
            Assert.Equal(34.7, crimes[0].Latitude);

            var microsoft = await store.GetMicrosoft365StatusAsync(now.AddDays(-7), CancellationToken.None);
            Assert.Equal(200, microsoft.FeedState?.LastHttpStatus);
            Assert.Equal(350, microsoft.FeedState?.LastDurationMs);
            Assert.True(microsoft.CloudJobEnabled);
            Assert.Equal(10, microsoft.CloudJobIntervalMinutes);
            Assert.Equal(new[] { 4, 5 }, microsoft.ActiveIncidents.Select(outage => outage.Id));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static async Task InsertCloudOutageAsync(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        int id,
        string provider,
        string title,
        bool resolved,
        DateTime updatedAt,
        string? statusCode = null)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO cloud_outages
                (id, provider, service, title, description, link, is_resolved,
                 updated_at, external_id, status_code)
            VALUES ($id, $provider, 'Service', $title, 'Description', 'https://status.example',
                    $resolved, $updated_at, $external_id, $status_code)
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$provider", provider);
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$resolved", resolved);
        command.Parameters.AddWithValue("$updated_at", FormatDate(updatedAt));
        command.Parameters.AddWithValue("$external_id", $"incident-{id}");
        command.Parameters.AddWithValue("$status_code", (object?)statusCode ?? DBNull.Value);
        await command.ExecuteNonQueryAsync();
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
