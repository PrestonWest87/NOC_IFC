using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAiopsSitrepActionStoreTests
{
    [Fact]
    public async Task LoadsBoundedRollingInputsAndSavesTheGeneratedSummary()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-sitrep-action-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            var now = DateTime.UtcNow;
            var since = now.AddHours(-24);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE articles (id INTEGER PRIMARY KEY, title TEXT, published_date DATETIME, score REAL);
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, updated_at DATETIME, status TEXT, expires_at DATETIME,
                        effective_at DATETIME, severity TEXT, title TEXT, location TEXT, description TEXT
                    );
                    CREATE TABLE cloud_outages (
                        id INTEGER PRIMARY KEY, updated_at DATETIME, provider TEXT, service TEXT, title TEXT
                    );
                    CREATE TABLE system_config (id INTEGER PRIMARY KEY, rolling_summary TEXT, rolling_summary_time DATETIME);
                    INSERT INTO system_config VALUES (1,NULL,NULL);
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO articles VALUES
                        (1,'Recent high', $now, 60),
                        (2,'Old high', $old, 99),
                        (3,'Recent low', $now, 49),
                        (4,'Recent top', $now, 90);
                    INSERT INTO regional_hazards VALUES
                        (1,$now,'active',NULL,NULL,'Severe','Tornado Warning','Central County','Details'),
                        (2,$now,'active',$expired,NULL,'Severe','Expired Warning','Central County','Details'),
                        (3,$now,'active',NULL,$future,'Severe','Future Warning','Central County','Details'),
                        (4,$old,'active',NULL,NULL,'Severe','Old Warning','Central County','Details');
                    INSERT INTO cloud_outages VALUES
                        (1,$now,'Azure','Compute','Active cloud issue'),
                        (2,$old,'Old Provider','Compute','Old cloud issue');
                    """;
                insert.Parameters.AddWithValue("$now", Format(now));
                insert.Parameters.AddWithValue("$old", Format(now.AddDays(-2)));
                insert.Parameters.AddWithValue("$expired", Format(now.AddMinutes(-1)));
                insert.Parameters.AddWithValue("$future", Format(now.AddMinutes(1)));
                await insert.ExecuteNonQueryAsync();
            }

            var store = new SqliteAiopsSitrepActionStore(connections);
            var inputs = await store.GetRollingBriefInputsAsync(since, now, CancellationToken.None);
            await store.SaveRollingSummaryAsync("Brief saved", now, CancellationToken.None);

            Assert.Equal(new[] { "Recent top", "Recent high" }, inputs.ArticleTitles);
            Assert.Equal(new[] { "Tornado Warning" }, inputs.Hazards.Select(hazard => hazard.Title));
            Assert.Equal(new[] { "Azure" }, inputs.CloudOutages.Select(outage => outage.Provider));
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var verify = connection.CreateCommand();
                verify.CommandText = "SELECT rolling_summary, rolling_summary_time FROM system_config WHERE id = 1";
                await using var reader = await verify.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("Brief saved", reader.GetString(0));
                Assert.Equal(Format(now), reader.GetString(1));
            }
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static string Format(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Unspecified)
            .ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
