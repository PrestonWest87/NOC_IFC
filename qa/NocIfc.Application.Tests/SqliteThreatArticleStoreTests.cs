using System.Globalization;
using System.Text.Json;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteThreatArticleStoreTests
{
    [Fact]
    public async Task PagesArticlesAndReturnsDetailWithKeywordWeightsAndIocs()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-threat-articles-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE keywords (id INTEGER PRIMARY KEY, word TEXT, weight INTEGER);
                    CREATE TABLE extracted_iocs (
                        id INTEGER PRIMARY KEY, article_id INTEGER, indicator_type TEXT,
                        indicator_value TEXT, context TEXT
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
                await InsertArticleAsync(connection, 1, "Router outage report", "Router service is disrupted", 90, "Infrastructure", false,
                    ["Router", "CVE-2026-0001"], now.AddHours(-1));
                await InsertArticleAsync(connection, 2, "Pinned low report", "Other details", 20, "Cyber", true,
                    ["malware"], now.AddHours(-2));
                await InsertArticleAsync(connection, 3, "Low priority story", "No matching term", 10, "Infrastructure", false,
                    [], now.AddHours(-3));
                await InsertArticleAsync(connection, 4, "Pinned router report", "Router bulletin", 70, "Infrastructure", true,
                    ["router"], now.AddHours(-4));
                await using var keywordSetup = connection.CreateCommand();
                keywordSetup.CommandText = """
                    INSERT INTO keywords VALUES (1, 'router', 5), (2, 'cve-2026-0001', 12);
                    INSERT INTO extracted_iocs VALUES (1, 1, 'CVE', 'CVE-2026-0001', 'Exploit reference');
                    """;
                await keywordSetup.ExecuteNonQueryAsync();
            }

            var store = new SqliteThreatArticleStore(connections);
            var live = await store.GetPageAsync("live", "All", 1, 10, null, 0, CancellationToken.None);
            Assert.Equal(1, live.Total);
            Assert.Equal(1, live.TotalPages);
            Assert.Equal(1, live.Items[0].Id);
            Assert.DoesNotContain("human_feedback", JsonSerializer.Serialize(live.Items[0]), StringComparison.Ordinal);

            var search = await store.GetPageAsync("search", "Infrastructure", 1, 5, "router", 50, CancellationToken.None);
            Assert.Equal(2, search.Total);
            Assert.Equal(new[] { 1, 4 }, search.Items.Select(article => article.Id));

            var low = await store.GetPageAsync("low", "All", 9, 5, null, 0, CancellationToken.None);
            Assert.Equal(1, low.Total);
            Assert.Equal(1, low.Page);
            Assert.Equal(3, low.Items[0].Id);

            var detail = Assert.IsType<NocIfc.Domain.Threat.ThreatArticleDetail>(
                await store.GetDetailAsync(1, CancellationToken.None));
            Assert.Equal(17, detail.TotalKeywordScore);
            Assert.Equal(new[] { ("Router", 5), ("CVE-2026-0001", 12) },
                detail.KeywordsWithWeights.Select(keyword => (keyword.Word, keyword.Weight)));
            var ioc = Assert.Single(detail.Iocs);
            Assert.Equal("CVE", ioc.IndicatorType);
            Assert.Equal("CVE-2026-0001", ioc.IndicatorValue);
            Assert.Null(await store.GetDetailAsync(999, CancellationToken.None));

            var selected = await store.GetByIdsAsync([4, 1, 999, 4], CancellationToken.None);
            Assert.Equal(new[] { 1, 4 }, selected.Select(article => article.Id));
            Assert.Empty(await store.GetByIdsAsync([], CancellationToken.None));
            Assert.True(await store.SaveAiBlufAsync(1, "Generated BLUF", CancellationToken.None));
            Assert.False(await store.SaveAiBlufAsync(999, "Missing article", CancellationToken.None));
            Assert.Equal("Generated BLUF", Assert.Single(await store.GetByIdsAsync([1], CancellationToken.None)).AiBluf);

            await store.TogglePinAsync(4, CancellationToken.None);
            await store.BoostScoreAsync(1, 20, CancellationToken.None);
            var pinned = await store.GetPinnedAsync(CancellationToken.None);
            Assert.Equal(new[] { 2 }, pinned.Select(article => article.Id));
            var liveArticles = await store.GetLiveAsync(15, now.AddDays(-1), CancellationToken.None);
            Assert.Equal(new[] { 1, 4 }, liveArticles.Select(article => article.Id));
            Assert.Equal(100d, liveArticles[0].Score);
            var internalRiskArticles = await store.GetRecentForInternalRiskAsync(10, now.AddHours(-2.5), CancellationToken.None);
            Assert.Equal(new[] { 1, 2 }, internalRiskArticles.Select(article => article.Id));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static async Task InsertArticleAsync(
        Microsoft.Data.Sqlite.SqliteConnection connection,
        int id,
        string title,
        string summary,
        int score,
        string category,
        bool pinned,
        IReadOnlyList<string> keywords,
        DateTime publishedDate)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO articles (
                id, title, link, summary, published_date, source, score, category,
                keywords_found, is_bubbled, story_group, human_feedback, full_content,
                ai_bluf, is_pinned, ingested_at, enrichment_status, enrichment_attempts,
                last_enrichment_error, last_enriched_at
            ) VALUES (
                $id, $title, $link, $summary, $published_date, 'Test Source', $score, $category,
                $keywords, 0, NULL, 4, 'Full content', 'BLUF', $is_pinned,
                $published_date, 'complete', 1, NULL, $published_date
            )
            """;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$link", $"https://example.test/article/{id}");
        command.Parameters.AddWithValue("$summary", summary);
        command.Parameters.AddWithValue("$published_date", publishedDate.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$score", score);
        command.Parameters.AddWithValue("$category", category);
        command.Parameters.AddWithValue("$keywords", JsonSerializer.Serialize(keywords));
        command.Parameters.AddWithValue("$is_pinned", pinned);
        await command.ExecuteNonQueryAsync();
    }
}
