using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteDailyFusionStoreTests
{
    [Fact]
    public async Task ReadsThePriorDayInputsAndUpsertsTheReportByLocalDate()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nocifc-daily-fusion-{Guid.NewGuid():N}.sqlite");
        using (File.Create(path)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{path}");
            var start = new DateTime(2026, 11, 25, 6, 0, 0, DateTimeKind.Utc);
            var end = start.AddDays(1);
            var now = end.AddHours(1);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE articles (
                        id INTEGER PRIMARY KEY, title TEXT, link TEXT, summary TEXT, published_date DATETIME,
                        source TEXT, score REAL, category TEXT, keywords_found TEXT, is_bubbled INTEGER,
                        story_group TEXT, full_content TEXT, ai_bluf TEXT, is_pinned INTEGER, ingested_at DATETIME,
                        enrichment_status TEXT, enrichment_attempts INTEGER, last_enrichment_error TEXT, last_enriched_at DATETIME
                    );
                    CREATE TABLE cve_items (
                        id INTEGER PRIMARY KEY, cve_id TEXT, vendor TEXT, product TEXT, vulnerability_name TEXT,
                        date_added DATETIME, description TEXT, required_action TEXT, due_date DATETIME
                    );
                    CREATE TABLE regional_hazards (
                        id INTEGER PRIMARY KEY, severity TEXT, title TEXT, location TEXT, description TEXT,
                        updated_at DATETIME, status TEXT, expires_at DATETIME, effective_at DATETIME
                    );
                    CREATE TABLE cloud_outages (
                        id INTEGER PRIMARY KEY, provider TEXT, service TEXT, title TEXT, updated_at DATETIME
                    );
                    CREATE TABLE daily_briefings (
                        id INTEGER PRIMARY KEY, report_date DATETIME UNIQUE, content TEXT, created_at DATETIME
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await using var insert = connection.CreateCommand();
                insert.CommandText = """
                    INSERT INTO articles (
                        id,title,published_date,source,score,category,keywords_found,is_bubbled,is_pinned,enrichment_status,enrichment_attempts
                    ) VALUES
                        (1,'Critical article',$start,'OSINT',85,'Cyber','[]',0,0,'complete',1),
                        (2,'Low score article',$start,'OSINT',79,'Cyber','[]',0,0,'complete',1),
                        (3,'Old article',$old,'OSINT',99,'Cyber','[]',0,0,'complete',1);
                    INSERT INTO cve_items VALUES
                        (1,'CVE-2026-0001','Vendor A','Router','Remote code execution',$start,NULL,NULL,NULL),
                        (2,'CVE-2026-0002','Vendor B','Switch','Old issue',$old,NULL,NULL,NULL);
                    INSERT INTO regional_hazards VALUES
                        (1,'Severe','Tornado Warning','Central','Active',$start,'active',NULL,NULL),
                        (2,'Severe','Expired Warning','Central','Expired',$start,'active',$expired,NULL),
                        (3,'Severe','Future Warning','Central','Future',$start,'active',NULL,$future);
                    INSERT INTO cloud_outages VALUES
                        (1,'Azure','Compute','Region issue',$start),
                        (2,'Old Provider','Storage','Old issue',$old);
                    """;
                insert.Parameters.AddWithValue("$start", Format(start.AddHours(1)));
                insert.Parameters.AddWithValue("$old", Format(start.AddDays(-1)));
                insert.Parameters.AddWithValue("$expired", Format(now.AddMinutes(-1)));
                insert.Parameters.AddWithValue("$future", Format(now.AddMinutes(1)));
                await insert.ExecuteNonQueryAsync();
            }

            var store = new SqliteDailyBriefingStore(connections);
            var inputs = await store.GetGenerationInputsAsync(start, end, now, CancellationToken.None);
            var reportDate = new DateTime(2026, 11, 25);
            await store.SaveAsync(reportDate, "first version", now, CancellationToken.None);
            await store.SaveAsync(reportDate, "updated version", now.AddMinutes(1), CancellationToken.None);

            Assert.Equal(new[] { "Critical article" }, inputs.Articles.Select(article => article.Title));
            Assert.Equal(new[] { "CVE-2026-0001" }, inputs.Cves.Select(cve => cve.CveId));
            Assert.Equal(new[] { "Tornado Warning" }, inputs.Hazards.Select(hazard => hazard.Title));
            Assert.Equal(new[] { "Azure" }, inputs.CloudOutages.Select(cloud => cloud.Provider));
            var saved = await store.GetAllAsync(CancellationToken.None);
            Assert.Single(saved);
            Assert.Equal("updated version", saved[0].Content);
            Assert.Equal(reportDate, saved[0].ReportDate);
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
