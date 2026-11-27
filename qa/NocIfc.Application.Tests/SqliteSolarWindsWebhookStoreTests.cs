using Microsoft.Data.Sqlite;
using NocIfc.Domain.AIOps;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteSolarWindsWebhookStoreTests
{
    [Fact]
    public async Task ResolvesKnownSitesSeparatelyAndUnknownSitesByNode()
    {
        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await using (var connection = connections.Create())
        {
            await connection.OpenAsync();
            await using var setup = connection.CreateCommand();
            setup.CommandText = """
                CREATE TABLE solarwinds_alerts (
                    id INTEGER PRIMARY KEY, event_type TEXT, severity TEXT, node_name TEXT,
                    ip_address TEXT, status TEXT, details TEXT, raw_payload TEXT, mapped_location TEXT,
                    received_at DATETIME, resolved_at DATETIME, is_dispatched BOOLEAN, is_ticketed BOOLEAN,
                    is_correlated BOOLEAN, needs_dispatch BOOLEAN, device_type TEXT, event_category TEXT
                );
                CREATE TABLE timeline_events (
                    id INTEGER PRIMARY KEY, timestamp DATETIME, source TEXT, event_type TEXT,
                    message TEXT, site_name TEXT
                );
                """;
            await setup.ExecuteNonQueryAsync();
        }
        var store = new SqliteSolarWindsWebhookStore(connections);
        var now = new DateTime(2026, 5, 2, 12, 0, 0, DateTimeKind.Utc);
        var alert = new SolarWindsWebhookEvent(
            "router-a", "10.0.0.1", "Critical", "P1-High", "Link Down", "Down",
            false, "COMMS_EQUIPMENT", "Central NOC", "Details");

        await store.PersistAsync(alert, "{\"Normalized_Alert_Level\":\"P1-High\"}", now, CancellationToken.None);
        await store.PersistAsync(alert with { EventType = "Second Link Down" }, "{}", now.AddMinutes(1), CancellationToken.None);
        await store.PersistAsync(alert with { SiteName = "Remote NOC" }, "{}", now.AddMinutes(2), CancellationToken.None);
        await store.PersistAsync(alert with { IsResolution = true, Status = "Resolved" }, "{}", now.AddMinutes(3), CancellationToken.None);

        Assert.Equal(3, Convert.ToInt32(Scalar(databasePath, "SELECT COUNT(*) FROM solarwinds_alerts")));
        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE status != 'Resolved'")));
        Assert.Equal("Remote NOC", Scalar(databasePath,
            "SELECT mapped_location FROM solarwinds_alerts WHERE status != 'Resolved'"));
        Assert.Equal(2, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE resolved_at IS NOT NULL")));
        await store.PersistAsync(alert with { SiteName = "Unknown", IsResolution = true, Status = "Resolved" },
            "{}", now.AddMinutes(4), CancellationToken.None);

        Assert.Equal(0, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE status != 'Resolved'")));
        Assert.Equal(3, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE resolved_at IS NOT NULL")));
        Assert.Equal(5, Convert.ToInt32(Scalar(databasePath, "SELECT COUNT(*) FROM timeline_events")));
        Assert.Equal("Webhook", Scalar(databasePath, "SELECT source FROM timeline_events LIMIT 1"));
        Assert.Equal("Central NOC", Scalar(databasePath, "SELECT site_name FROM timeline_events LIMIT 1"));
    }

    private static object? Scalar(string databasePath, string query)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = query;
        var result = command.ExecuteScalar();
        return result is DBNull ? null : result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-solarwinds-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
