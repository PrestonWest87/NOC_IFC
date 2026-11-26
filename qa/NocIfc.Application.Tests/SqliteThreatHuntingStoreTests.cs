using System.Globalization;
using NocIfc.Domain.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteThreatHuntingStoreTests
{
    [Fact]
    public async Task ReadsIocsSearchesArticleTextAndPagesElasticCache()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-threat-hunting-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE articles (
                        id INTEGER PRIMARY KEY, title TEXT, link TEXT, summary TEXT,
                        published_date DATETIME, source TEXT, score REAL, category TEXT,
                        keywords_found TEXT, is_bubbled INTEGER, story_group TEXT,
                        human_feedback INTEGER, full_content TEXT, ai_bluf TEXT,
                        is_pinned INTEGER, ingested_at DATETIME, enrichment_status TEXT,
                        enrichment_attempts INTEGER, last_enrichment_error TEXT, last_enriched_at DATETIME
                    );
                    CREATE TABLE extracted_iocs (
                        id INTEGER PRIMARY KEY, article_id INTEGER, indicator_type TEXT,
                        indicator_value TEXT, context TEXT, detected_at DATETIME
                    );
                    CREATE TABLE elastic_events (
                        id TEXT PRIMARY KEY, timestamp DATETIME, index_name TEXT, severity TEXT,
                        message TEXT, source_ip TEXT, event_category TEXT
                    );
                    INSERT INTO articles VALUES
                        (1,'Volt Typhoon activity','https://example.test/1','Power grid outage', $recent, 'Threat Intel', 80, 'Cyber', '[]',0,NULL,7,'full-content hit',NULL,0,$recent,'complete',1,NULL,NULL),
                        (2,'Other article','https://example.test/2','No match','2026-01-01 00:00:00','Old Source',20,'General','[]',0,NULL,5,NULL,NULL,0,'2026-01-01 00:00:00','complete',0,NULL,NULL);
                    INSERT INTO extracted_iocs VALUES
                        (1,1,'CVE','CVE-2026-0001','First context',$recent),
                        (2,99,'IPv4','192.0.2.44','Orphan source',$recent2),
                        (3,1,'CVE','CVE-2026-0001','Repeated context',$recent3),
                        (4,1,'Domain','old.example','Old indicator','2026-01-01 00:00:00');
                    INSERT INTO elastic_events VALUES
                        ('event-1',$recent,'index-a','critical','New event','192.0.2.1','network'),
                        ('event-2',$recent2,'index-b','high','Older event',NULL,'endpoint'),
                        ('legacy-event','2026-01-01 00:00:00','index-old','warning','Old event',NULL,'endpoint');
                    """;
                setup.Parameters.AddWithValue("$recent", FormatDate(now.AddMinutes(-10)));
                setup.Parameters.AddWithValue("$recent2", FormatDate(now.AddMinutes(-20)));
                setup.Parameters.AddWithValue("$recent3", FormatDate(now.AddMinutes(-30)));
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteThreatHuntingStore(connections);
            var iocs = await store.GetRecentIocsAsync(now.AddDays(-3), 1000, CancellationToken.None);
            Assert.Equal(new[] { 1, 2, 3 }, iocs.Select(ioc => ioc.Id));
            Assert.Equal("Volt Typhoon activity", iocs[0].SourceTitle);
            Assert.Null(iocs[1].SourceTitle);
            Assert.Null(iocs[1].SourceLink);

            var search = await store.SearchArticlesAsync(now.AddDays(-30), ["Volt Typhoon", "full-content"], 30, CancellationToken.None);
            Assert.Equal(new[] { 1 }, search.Select(article => article.Id));

            var elastic = await store.GetElasticEventsAsync(now.AddHours(-1), 2, 1, 1, CancellationToken.None);
            Assert.Equal(2, elastic.Total);
            Assert.Equal(2, elastic.Page);
            Assert.Single(elastic.Items);
            Assert.Equal("event-2", elastic.Items[0].Id);
            Assert.Equal(1, elastic.PageSize);

            var imported = await store.AddElasticEventsAsync(
            [
                new("index-a:legacy-event", now, "index-a", "HIGH", "Duplicate", null, null, "legacy-event"),
                new("index-b:fresh-event", now, "index-b", "CRITICAL", "New", null, null, "fresh-event"),
                new("index-b:fresh-event", now, "index-b", "CRITICAL", "New", null, null, "fresh-event"),
            ],
            CancellationToken.None);
            Assert.Equal(1, imported);
            var afterSync = await store.GetElasticEventsAsync(now.AddHours(-1), 1, 20, 1, CancellationToken.None);
            Assert.Equal(3, afterSync.Total);
            Assert.Contains(afterSync.Items, item => item.Id == "index-b:fresh-event");
            Assert.DoesNotContain(afterSync.Items, item => item.Id == "index-a:legacy-event");
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
