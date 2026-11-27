using NocIfc.Application.Features.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteKeywordAnalysisStoreTests
{
    [Fact]
    public async Task ReturnsFrontendKeywordCategoryAndScoreAnalytics()
    {
        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await CreateSchemaAsync(connections);
        await SeedAnalyticsAsync(connections);
        var store = new SqliteKeywordAnalysisStore(connections);

        var overview = await store.GetOverviewAsync(CancellationToken.None);
        Assert.Equal(2, overview.TotalKeywords);
        Assert.Equal(3, overview.TotalArticles);
        Assert.Equal(70, overview.AverageWeight);
        Assert.Equal(2, overview.KeywordsUsed);
        Assert.Equal(2, overview.ArticlesWithKeywords);
        Assert.Equal(1, overview.ArticlesWithoutKeywords);

        var stats = await store.GetKeywordStatsAsync("trigger_count", true, "", 100, CancellationToken.None);
        Assert.Equal("ransomware", stats[0].Word);
        Assert.Equal(2, stats[0].TriggerCount);
        Assert.Equal(160, stats[0].AverageScoreContribution);

        var categories = await store.GetCategoryDistributionAsync(0, CancellationToken.None);
        Assert.Equal("General", categories[0].Category);
        Assert.Equal(2, categories[0].Count);
        Assert.Equal(66.7, categories[0].Percent);
        var details = await store.GetCategoryDetailsAsync("General", 0, CancellationToken.None);
        Assert.NotNull(details);
        Assert.Equal(2, details.TotalArticles);
        Assert.Equal(60, details.AverageScore);
        Assert.Equal("ransomware", details.TopKeywords[0].Word);

        var timeline = await store.GetTimelineAsync("ransomware", 0, "day", CancellationToken.None);
        Assert.Equal(3, timeline.Count);
        Assert.Equal(2, timeline.Sum(point => point.MatchedArticles));
        var articles = await store.GetKeywordArticlesAsync("RANSOMWARE", 10, CancellationToken.None);
        Assert.Equal(2, articles.Count);

        var scores = await store.GetScoreDistributionAsync(0, 10, CancellationToken.None);
        Assert.Equal(11, scores.Count);
        Assert.Equal(1, scores.Single(bucket => bucket.Bucket == "90-99").Count);
        Assert.Equal("General", scores.Single(bucket => bucket.Bucket == "90-99").TopCategory);

        var matrix = await store.GetCategoryKeywordMatrixAsync(20, CancellationToken.None);
        Assert.Equal(["Cyber: Malware & Threats", "General"], matrix.Categories);
        Assert.Equal(["ransomware", "outage"], matrix.Keywords);
        Assert.Equal(1, matrix.Matrix[1]["ransomware"]);
        Assert.Equal(1, matrix.Matrix[0]["outage"]);
    }

    [Fact]
    public async Task RecategorizationUpdatesChangedRowsInIdOrderedBatches()
    {
        const string title = "CVE-2026-1234 vulnerability patch available";
        Assert.Equal("Cyber: Exploits & Vulns", ArticleCategorizer.CategorizeText(title));

        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await CreateSchemaAsync(connections);
        await using (var connection = connections.Create())
        {
            await connection.OpenAsync();
            await using var insert = connection.CreateCommand();
            insert.CommandText = """
                INSERT INTO articles (id, title, summary, source, published_date, score, category, keywords_found)
                VALUES (1, 'CVE-2026-1234 vulnerability patch available', '', 'Threat Feed',
                        '2026-11-27 12:00:00.000000', 70, 'General', '[]')
                """;
            await insert.ExecuteNonQueryAsync();
        }
        var store = new SqliteKeywordAnalysisStore(connections);
        var commands = new KeywordAnalysisCommands(store);
        var batch = await store.GetRecategorizationBatchAsync(0, 10, CancellationToken.None);
        Assert.Equal(1, batch[0].Id);
        Assert.Equal("General", batch[0].Category);
        Assert.Equal("Cyber: Exploits & Vulns", ArticleCategorizer.CategorizeText(
            $"{batch[0].Title} {batch[0].Summary}"));

        var first = await commands.RecategorizeAsync(CancellationToken.None);
        var second = await commands.RecategorizeAsync(CancellationToken.None);
        var category = await store.GetCategoryDetailsAsync("Cyber: Exploits & Vulns", 0, CancellationToken.None);

        Assert.Equal(1, first.Total);
        Assert.Equal(1, first.Changed);
        Assert.Equal(0, second.Changed);
        Assert.Equal(1, category?.TotalArticles);
    }

    private static async Task CreateSchemaAsync(SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var setup = connection.CreateCommand();
        setup.CommandText = """
            CREATE TABLE keywords (id INTEGER PRIMARY KEY, word TEXT, weight INTEGER);
            CREATE TABLE articles (
                id INTEGER PRIMARY KEY, title TEXT, summary TEXT, source TEXT,
                published_date DATETIME, score REAL, category TEXT, keywords_found TEXT
            );
            """;
        await setup.ExecuteNonQueryAsync();
    }

    private static async Task SeedAnalyticsAsync(SqliteConnectionFactory connections)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync();
        await using var seed = connection.CreateCommand();
        seed.CommandText = """
            INSERT INTO keywords (id, word, weight) VALUES (1, 'ransomware', 80), (2, 'outage', 60);
            INSERT INTO articles (id, title, summary, source, published_date, score, category, keywords_found) VALUES
                (1, 'Utility ransomware incident', 'Ransomware affected a utility.', 'Threat Feed', '2026-11-27 12:00:00.000000', 80, 'Cyber: Malware & Threats', '["ransomware","outage"]'),
                (2, 'Routine service update', 'No keyword match.', 'Operations Feed', '2026-11-26 12:00:00.000000', 20, 'General', '[]'),
                (3, 'Another ransomware report', 'Follow-up.', 'Threat Feed', '2026-11-24 12:00:00.000000', 100, 'General', '["ransomware"]');
            """;
        await seed.ExecuteNonQueryAsync();
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-keyword-analysis-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
