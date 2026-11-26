using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAiopsDashboardStoreTests
{
    [Fact]
    public async Task AppliesSiteScopeBeforeTimelineLimitAndCountsAcknowledgedUnresolvedAlerts()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-aiops-board-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            var now = DateTime.UtcNow;
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE solarwinds_alerts (
                        id INTEGER PRIMARY KEY, event_type TEXT, severity TEXT, node_name TEXT, ip_address TEXT,
                        status TEXT, sw_timestamp TEXT, details TEXT, node_link TEXT, raw_payload TEXT,
                        mapped_location TEXT, received_at DATETIME, resolved_at DATETIME,
                        is_dispatched INTEGER, is_ticketed INTEGER, is_correlated INTEGER, needs_dispatch INTEGER,
                        ai_root_cause TEXT, device_type TEXT, event_category TEXT, acknowledged_by TEXT,
                        acknowledged_at DATETIME, dispatched_by TEXT, dispatched_at DATETIME, onpage_sent_at DATETIME
                    );
                    CREATE TABLE timeline_events (
                        id INTEGER PRIMARY KEY, timestamp DATETIME, source TEXT, event_type TEXT,
                        message TEXT, site_name TEXT
                    );
                    CREATE TABLE regional_outages (
                        id INTEGER PRIMARY KEY, outage_type TEXT, provider TEXT, description TEXT,
                        affected_area TEXT, lat REAL, lon REAL, radius_km REAL, detected_at DATETIME,
                        is_resolved INTEGER
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO solarwinds_alerts(
                        id,event_type,severity,node_name,ip_address,status,details,raw_payload,mapped_location,
                        received_at,is_dispatched,is_ticketed,is_correlated,needs_dispatch,event_category)
                    VALUES
                        (1,'Down','Critical','router-1','192.0.2.1','Down','timeout','{"source":"test"}','Central NOC',$now,0,0,0,0,'network'),
                        (2,'Down','High','router-2','192.0.2.2','Acknowledged','link loss',NULL,'Central NOC',$now,0,0,1,0,'network'),
                        (3,'Down','Critical','server-1','192.0.2.3','Down','timeout',NULL,'Field Office',$now,0,0,0,0,'compute'),
                        (4,'Down','Critical','router-3','192.0.2.4','Resolved','fixed',NULL,'Central NOC',$now,0,0,0,0,'network');
                    INSERT INTO timeline_events VALUES
                        (1,$now,'SolarWinds','Down','Warning?🔥','Central NOC'),
                        (2,$old,'SolarWinds','Down','Other site event','Field Office'),
                        (3,$now,'System','Notice','Unscoped event',NULL);
                    INSERT INTO regional_outages VALUES
                        (1,'Power','Utility','Loss','Central NOC region',34.7,-92.2,10,$now,0),
                        (2,'Power','Utility','Loss','Field Office region',35.0,-92.0,10,$now,0);
                    """;
                insert.Parameters.AddWithValue("$now", Format(now));
                insert.Parameters.AddWithValue("$old", Format(now.AddMinutes(-1)));
                await insert.ExecuteNonQueryAsync();
            }

            var store = new SqliteAiopsDashboardStore(connections);
            var allowed = new HashSet<string>(["Central NOC"], StringComparer.Ordinal);
            var alerts = await store.GetUnresolvedAlertsAsync(allowed, CancellationToken.None);
            var events = await store.GetTimelineEventsAsync(allowed, 50, CancellationToken.None);
            var counts = await store.GetActiveIssueCountsAsync(allowed, CancellationToken.None);
            var outages = await store.GetUnresolvedOutagesAsync(CancellationToken.None);

            Assert.Single(alerts);
            Assert.Equal(1, alerts[0].Id);
            Assert.Equal("{\"source\":\"test\"}", alerts[0].RawPayloadJson);
            Assert.Single(events);
            Assert.Equal("Warning", events[0].Message);
            Assert.Equal(2, counts["Central NOC"]);
            Assert.Equal(2, outages.Count);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Format(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
