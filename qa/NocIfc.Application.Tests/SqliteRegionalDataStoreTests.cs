using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRegionalDataStoreTests
{
    [Fact]
    public async Task ReadsRequestedLayersFeedHealthAndOnlyCurrentNwsEventTypes()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-regional-data-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE geojson_cache (
                        feed_name TEXT PRIMARY KEY, data TEXT, updated_at DATETIME,
                        last_attempt_at DATETIME, last_success_at DATETIME, last_error TEXT,
                        last_http_status INTEGER, last_duration_ms INTEGER, retry_after_at DATETIME,
                        feature_count INTEGER, coverage_summary TEXT
                    );
                    INSERT INTO geojson_cache VALUES
                        ('spc_day1','{"type":"FeatureCollection","features":[]}',$updated,$attempt,$success,NULL,200,17,NULL,4,'{"summary":"spc"}'),
                        ('nws_region',NULL,$updated,$attempt,$success,'temporary failure',503,31,NULL,1,NULL);
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, hazard_type TEXT, status TEXT,
                        expires_at DATETIME, effective_at DATETIME
                    );
                    INSERT INTO regional_hazards VALUES
                        (1,'Tornado Warning','active',$future,$past),
                        (2,'Expired Warning','active',$past,$past),
                        (3,'Future Warning','active',$future,$future),
                        (4,'Resolved Warning','resolved',$future,$past);
                    """;
                setup.Parameters.AddWithValue("$updated", FormatDate(now.AddMinutes(-1)));
                setup.Parameters.AddWithValue("$attempt", FormatDate(now));
                setup.Parameters.AddWithValue("$success", FormatDate(now.AddMinutes(-1)));
                setup.Parameters.AddWithValue("$future", FormatDate(now.AddHours(1)));
                setup.Parameters.AddWithValue("$past", FormatDate(now.AddMinutes(-1)));
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteRegionalDataStore(connections);
            var layers = await store.GetGeoJsonLayersAsync(["spc_day1", "missing"], CancellationToken.None);
            Assert.Equal("{\"type\":\"FeatureCollection\",\"features\":[]}", layers["spc_day1"]);
            Assert.False(layers.ContainsKey("missing"));
            var status = await store.GetGeoJsonFeedStatusesAsync(["spc_day1", "nws_region"], CancellationToken.None);
            Assert.Equal(4, status["spc_day1"].FeatureCount);
            Assert.Equal("temporary failure", status["nws_region"].LastError);
            Assert.Equal(503, status["nws_region"].LastHttpStatus);
            var eventTypes = await store.GetActiveNwsEventTypesAsync(now, CancellationToken.None);
            Assert.Equal(["Tornado Warning"], eventTypes);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
