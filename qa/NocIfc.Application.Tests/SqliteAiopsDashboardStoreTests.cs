using System.Globalization;
using NocIfc.Domain.AIOps;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAiopsDashboardStoreTests
{
    [Fact]
    public async Task AppliesSiteScopesAndPersistsAlertWorkflowsAtomically()
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
                    CREATE TABLE monitored_locations (
                        id INTEGER PRIMARY KEY, name TEXT, status_modified_by TEXT, status_modified_at DATETIME,
                        under_maintenance INTEGER, maintenance_etr DATETIME, maintenance_reason TEXT
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO solarwinds_alerts(
                        id,event_type,severity,node_name,ip_address,status,details,raw_payload,mapped_location,
                        received_at,is_dispatched,is_ticketed,is_correlated,needs_dispatch,event_category)
                    VALUES
                        (1,'Down','Critical','router-1','192.0.2.1','Down','timeout','{"source":"test"}','Central NOC',$now,1,0,0,0,'network'),
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
                    INSERT INTO monitored_locations VALUES
                        (1,'Central NOC',NULL,NULL,0,NULL,NULL),(2,'Field Office',NULL,NULL,0,NULL,NULL);
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

            var needsDispatch = await store.SetSiteNeedsDispatchAsync(
                "Central NOC", true, "operator", now, allowed, CancellationToken.None);
            Assert.Equal(AiopsNeedsDispatchOutcome.Updated, needsDispatch.Outcome);
            Assert.Equal(1, needsDispatch.UpdatedAlerts);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var verify = connection.CreateCommand();
                verify.CommandText = """
                    SELECT a.is_dispatched, a.needs_dispatch, l.status_modified_by
                    FROM solarwinds_alerts a JOIN monitored_locations l ON l.name = a.mapped_location
                    WHERE a.id = 1
                    """;
                await using var reader = await verify.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.False(reader.GetBoolean(0));
                Assert.True(reader.GetBoolean(1));
                Assert.Equal("operator", reader.GetString(2));
            }
            Assert.Equal(AiopsNeedsDispatchOutcome.SiteScopeDenied,
                (await store.SetSiteNeedsDispatchAsync(
                    "Field Office", true, "operator", now, allowed, CancellationToken.None)).Outcome);
            Assert.Equal(AiopsNeedsDispatchOutcome.SiteNotFound,
                (await store.SetSiteNeedsDispatchAsync(
                    "Missing", false, "admin", now, null, CancellationToken.None)).Outcome);
            var etr = new DateTime(2026, 11, 27);
            Assert.True(await store.SetSiteMaintenanceAsync(
                "Central NOC", true, etr, "planned work", "maintainer", now, CancellationToken.None));
            Assert.False(await store.SetSiteMaintenanceAsync(
                "Missing", true, etr, "planned work", "maintainer", now, CancellationToken.None));
            Assert.True(await store.SetSiteMaintenanceAsync(
                "Central NOC", false, etr, "stale client reason", "operator", now.AddMinutes(1), CancellationToken.None));
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var verify = connection.CreateCommand();
                verify.CommandText = """
                    SELECT under_maintenance, maintenance_etr, maintenance_reason, status_modified_by, status_modified_at
                    FROM monitored_locations WHERE name = 'Central NOC'
                    """;
                await using var reader = await verify.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.False(reader.GetBoolean(0));
                Assert.True(reader.IsDBNull(1));
                Assert.True(reader.IsDBNull(2));
                Assert.Equal("operator", reader.GetString(3));
                Assert.Equal(Format(now.AddMinutes(1)), reader.GetString(4));
            }

            Assert.False(await store.AcknowledgeAlertsAsync(
                [1, 3], "operator", now, allowed, CancellationToken.None));
            Assert.True(await store.AcknowledgeAlertsAsync(
                [1, 1], "operator", now, allowed, CancellationToken.None));
            Assert.False(await store.AcknowledgeAlertsAsync(
                [999], "operator", now, allowed, CancellationToken.None));
            Assert.True(await store.AcknowledgeAlertsAsync(
                [999], "admin", now, null, CancellationToken.None));
            Assert.Equal(AiopsNeedsDispatchOutcome.ActiveAlertRequired,
                (await store.SetSiteNeedsDispatchAsync(
                    "Central NOC", true, "operator", now, allowed, CancellationToken.None)).Outcome);
            Assert.False(await store.SetClusterDispatchAsync(
                [1, 3], true, "dispatcher", now, allowed, CancellationToken.None));
            Assert.True(await store.SetClusterDispatchAsync(
                [1], true, "dispatcher", now.AddMinutes(1), allowed, CancellationToken.None));
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var verify = connection.CreateCommand();
                verify.CommandText = "SELECT is_dispatched, needs_dispatch FROM solarwinds_alerts WHERE id = 1";
                await using var reader = await verify.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.True(reader.GetBoolean(0));
                Assert.False(reader.GetBoolean(1));
            }
            Assert.True(await store.SetClusterDispatchAsync(
                [1], false, "dispatcher", now.AddMinutes(2), allowed, CancellationToken.None));

            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var verify = connection.CreateCommand();
                verify.CommandText = """
                    SELECT a.is_correlated, a.needs_dispatch, a.acknowledged_by, a.acknowledged_at,
                           a.is_dispatched, a.dispatched_by, a.dispatched_at,
                           l.status_modified_by, l.status_modified_at
                    FROM solarwinds_alerts a JOIN monitored_locations l ON l.name = a.mapped_location
                    WHERE a.id = 1
                    """;
                await using var reader = await verify.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.True(reader.GetBoolean(0));
                Assert.False(reader.GetBoolean(1));
                Assert.Equal("operator", reader.GetString(2));
                Assert.Equal(Format(now), reader.GetString(3));
                Assert.False(reader.GetBoolean(4));
                Assert.Equal("dispatcher", reader.GetString(5));
                Assert.Equal(Format(now.AddMinutes(2)), reader.GetString(6));
                Assert.Equal("dispatcher", reader.GetString(7));
                Assert.Equal(Format(now.AddMinutes(2)), reader.GetString(8));
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Format(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
