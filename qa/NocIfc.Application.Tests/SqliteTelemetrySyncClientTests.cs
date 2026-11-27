using System.Net;
using Microsoft.Data.Sqlite;
using NocIfc.Infrastructure.Integrations.Weather;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteTelemetrySyncClientTests
{
    [Fact]
    public async Task ReplacesProviderOutagesAndDeduplicatesActiveBgpAnomalies()
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
                CREATE TABLE system_config (id INTEGER PRIMARY KEY, monitored_asns TEXT);
                INSERT INTO system_config VALUES (1, 'AS123, as456');
                CREATE TABLE regional_outages (
                    id INTEGER PRIMARY KEY, outage_type TEXT, provider TEXT, description TEXT,
                    affected_area TEXT, lat REAL, lon REAL, radius_km REAL, detected_at DATETIME,
                    is_resolved BOOLEAN
                );
                INSERT INTO regional_outages (outage_type, provider, is_resolved)
                    VALUES ('Power', 'ORNL ODIN', 0), ('ISP', 'IODA', 0);
                CREATE TABLE bgp_anomalies (
                    id INTEGER PRIMARY KEY, asn TEXT, event_type TEXT, description TEXT,
                    detected_at DATETIME, is_resolved BOOLEAN
                );
                """;
            await setup.ExecuteNonQueryAsync();
        }
        using var http = new HttpClient(new FixtureTelemetryHandler());
        var sync = new TelemetrySyncClient(http, connections);

        var first = await sync.SyncAsync(CancellationToken.None);
        var second = await sync.SyncAsync(CancellationToken.None);

        Assert.Equal(1, first.PowerRows);
        Assert.Equal(1, first.BgpAnomaliesAdded);
        Assert.Equal(1, first.IodaRows);
        Assert.Equal(0, second.BgpAnomaliesAdded);
        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM regional_outages WHERE provider = 'ORNL ODIN'")));
        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM regional_outages WHERE provider = 'IODA'")));
        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM bgp_anomalies WHERE asn = 'AS123' AND is_resolved = 0")));
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

    private sealed class FixtureTelemetryHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            var body = uri.Host switch
            {
                "ornl.opendatasoft.com" => """{"results":[{"county":"PULASKI","customers_out":500},{"county":"SALINE","customers_out":25}]}""",
                "stat.ripe.net" => uri.Query.Contains("AS123", StringComparison.Ordinal)
                    ? """{"data":{"visibility":{"v4":{"risk":0.8}}}}"""
                    : """{"data":{"visibility":{"v4":{"risk":0.2}}}}""",
                "api.ioda.inetintel.cc.gatech.edu" => uri.Query.Contains("US-AR", StringComparison.Ordinal)
                    ? """{"data":[{"datasource":"test"}]}"""
                    : """{"data":[]}""",
                _ => "{}",
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body),
            });
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-telemetry-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
