using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAiopsRcaAnalysisStoreTests
{
    [Fact]
    public async Task LoadsOnlyActiveCorrelationContextAndReadsHistoryOnRequest()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-aiops-rca-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE cloud_outages (id INTEGER PRIMARY KEY, provider TEXT, is_resolved INTEGER);
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, hazard_type TEXT, location TEXT, status TEXT,
                        expires_at DATETIME, effective_at DATETIME
                    );
                    CREATE TABLE bgp_anomalies (id INTEGER PRIMARY KEY, asn TEXT, is_resolved INTEGER);
                    CREATE TABLE solarwinds_alerts (
                        id INTEGER PRIMARY KEY, node_name TEXT, device_type TEXT, mapped_location TEXT,
                        raw_payload TEXT, status TEXT, received_at DATETIME
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO cloud_outages VALUES (1,'Azure',0),(2,'Old Provider',1);
                    INSERT INTO regional_hazards VALUES
                        (1,'Tornado Warning','Central District','active',NULL,NULL),
                        (2,'Expired Warning','Central District','active',$expired,NULL),
                        (3,'Future Warning','Central District','active',NULL,$future),
                        (4,'Inactive Warning','Central District','inactive',NULL,NULL);
                    INSERT INTO bgp_anomalies VALUES (1,'AS123',0),(2,'AS999',1);
                    INSERT INTO solarwinds_alerts VALUES
                        (1,'router-1','Router','Central NOC','{}','Down',$now),
                        (2,'router-old','Router','Central NOC','{}','Resolved',$history_old);
                    """;
                insert.Parameters.AddWithValue("$now", Format(now));
                insert.Parameters.AddWithValue("$expired", Format(now.AddMinutes(-1)));
                insert.Parameters.AddWithValue("$future", Format(now.AddMinutes(1)));
                insert.Parameters.AddWithValue("$history_old", Format(now.AddDays(-61)));
                await insert.ExecuteNonQueryAsync();
            }

            var store = new SqliteAiopsRcaAnalysisStore(connections);
            var withHistory = await store.GetAnalysisContextAsync(now, now.AddDays(-60), true, CancellationToken.None);
            var withoutHistory = await store.GetAnalysisContextAsync(now, now.AddDays(-60), false, CancellationToken.None);

            Assert.Equal(new[] { "Azure" }, withHistory.CloudOutages.Select(outage => outage.Provider));
            Assert.Equal(new[] { "Tornado Warning" }, withHistory.ActiveWeather.Select(hazard => hazard.HazardType));
            Assert.Equal(new[] { "AS123" }, withHistory.ActiveBgp.Select(anomaly => anomaly.Asn));
            Assert.Equal(new[] { "router-1" }, withHistory.RecentAlerts.Select(alert => alert.NodeName));
            Assert.Empty(withoutHistory.RecentAlerts);
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Format(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
