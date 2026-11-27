using System.Globalization;
using NocIfc.Domain.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRssIngestionStoreTests
{
    [Fact]
    public async Task InsertsArticlesAndIndicatorsThenRemovesRecentSimilarTitles()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-rss-ingestion-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE articles (
                        id INTEGER PRIMARY KEY, title TEXT, link TEXT UNIQUE, summary TEXT, published_date DATETIME,
                        source TEXT, score REAL, category TEXT, keywords_found TEXT, is_bubbled INTEGER,
                        story_group TEXT, full_content TEXT, ai_bluf TEXT, is_pinned INTEGER,
                        ingested_at DATETIME, enrichment_status TEXT, enrichment_attempts INTEGER,
                        last_enrichment_error TEXT, last_enriched_at DATETIME
                    );
                    CREATE TABLE extracted_iocs (
                        id INTEGER PRIMARY KEY, article_id INTEGER, indicator_type TEXT,
                        indicator_value TEXT, context TEXT, detected_at DATETIME
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var now = DateTime.UtcNow.Date.AddHours(12);
            var original = Article(
                "Ransomware attack disrupts utility control systems",
                "https://source.example.test/1", now,
                [new RssArticleIoc("Taxonomy", "CVE", "CVE-2026-1234", "...incident context...")]);
            var duplicateLink = Article("Different title", original.Link, now.AddMinutes(1), []);
            var similarTitle = Article(
                "Ransomware attack disrupts utility control system",
                "https://source.example.test/2", now.AddMinutes(2), []);
            var longTitle = new string('x', 4_097);
            var longTitleFirst = Article(longTitle, "https://source.example.test/3", now.AddMinutes(3), []);
            var longTitleSecond = Article(longTitle, "https://source.example.test/4", now.AddMinutes(4), []);
            var store = new SqliteRssIngestionStore(connections);

            var inserted = await store.InsertArticlesAsync(
                [original, duplicateLink, similarTitle, longTitleFirst, longTitleSecond], CancellationToken.None);

            Assert.Equal(4, inserted);
            var knownLinks = await store.GetRecentLinksAsync(now.AddDays(-7), CancellationToken.None);
            Assert.Equal(4, knownLinks.Count);
            Assert.Equal(2, await store.DeduplicateRecentArticlesAsync(now.AddHours(-24), CancellationToken.None));
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var count = connection.CreateCommand();
                count.CommandText = "SELECT COUNT(*) FROM articles";
                Assert.Equal(2L, await count.ExecuteScalarAsync());
                await using var iocCount = connection.CreateCommand();
                iocCount.CommandText = "SELECT COUNT(*) FROM extracted_iocs";
                Assert.Equal(1L, await iocCount.ExecuteScalarAsync());
                await using var stored = connection.CreateCommand();
                stored.CommandText = "SELECT enrichment_status, is_bubbled, keywords_found FROM articles LIMIT 1";
                await using var reader = await stored.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("pending", reader.GetString(0));
                Assert.True(reader.GetBoolean(1));
                Assert.Equal("[\"cve\"]", reader.GetString(2));
            }
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static RssArticleIngestCandidate Article(
        string title,
        string link,
        DateTime publishedAt,
        IReadOnlyList<RssArticleIoc> iocs) => new(
        title,
        link,
        "Ransomware attack summary",
        "Threat Feed",
        publishedAt,
        90,
        "Cyber: Malware & Threats",
        ["cve"],
        true,
        iocs);
}
