using Microsoft.Data.Sqlite;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteArticleEnrichmentStoreTests
{
    [Fact]
    public async Task ClaimsBoundedHighScoreArticlesAndPersistsEnrichmentOutcomes()
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
                CREATE TABLE articles (
                    id INTEGER PRIMARY KEY, link TEXT, score REAL, ingested_at DATETIME,
                    enrichment_status TEXT, enrichment_attempts INTEGER, full_content TEXT,
                    last_enrichment_error TEXT, last_enriched_at DATETIME
                );
                INSERT INTO articles VALUES
                    (1, 'https://news.example/1', 80, '2026-01-01', 'pending', 0, NULL, NULL, NULL),
                    (2, 'https://news.example/2', 70, '2026-01-02', 'failed', 2, NULL, 'old error', NULL),
                    (3, 'https://news.example/3', 39, '2026-01-03', 'pending', 0, NULL, NULL, NULL),
                    (4, 'https://news.example/4', 90, '2026-01-04', 'failed', 3, NULL, NULL, NULL);
                """;
            await setup.ExecuteNonQueryAsync();
        }
        var store = new SqliteArticleEnrichmentStore(connections);

        var claimed = await store.ClaimPendingAsync(25, CancellationToken.None);
        await store.SaveEnrichedAsync(1, "full article text", new DateTime(2026, 1, 5, 0, 0, 0, DateTimeKind.Utc), CancellationToken.None);
        await store.SaveFailureAsync(2, "no content", CancellationToken.None);

        Assert.Equal(new[] { 1, 2 }, claimed.Select(article => article.Id));
        Assert.Equal("enriched", Scalar(databasePath, "SELECT enrichment_status FROM articles WHERE id = 1"));
        Assert.Equal("full article text", Scalar(databasePath, "SELECT full_content FROM articles WHERE id = 1"));
        Assert.Null(Scalar(databasePath, "SELECT last_enrichment_error FROM articles WHERE id = 1"));
        Assert.Equal("failed", Scalar(databasePath, "SELECT enrichment_status FROM articles WHERE id = 2"));
        Assert.Equal(3, Convert.ToInt32(Scalar(databasePath, "SELECT enrichment_attempts FROM articles WHERE id = 2")));
        Assert.Equal(0, Convert.ToInt32(Scalar(databasePath, "SELECT enrichment_attempts FROM articles WHERE id = 3")));
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

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-enrichment-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
