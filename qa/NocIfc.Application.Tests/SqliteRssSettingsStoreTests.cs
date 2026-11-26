using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRssSettingsStoreTests
{
    [Fact]
    public async Task ReadsAddsUpdatesAndDeletesKeywordsAndFeedsWithDuplicateProtection()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-rss-settings-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE keywords (id INTEGER PRIMARY KEY, word TEXT UNIQUE, weight INTEGER);
                    CREATE TABLE feed_sources (id INTEGER PRIMARY KEY, url TEXT UNIQUE, name TEXT, is_active INTEGER);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteRssSettingsStore(connections);
            await store.AddKeywordsAsync(
                [new(0, "router", 50), new(0, "malware", 10), new(0, "router", 20)],
                CancellationToken.None);
            await store.AddFeedsAsync(
                [new(0, "https://feeds.example/rss", "Example", true), new(0, "https://feeds.example/rss", "Duplicate", true)],
                CancellationToken.None);

            var initial = await store.GetCatalogAsync(CancellationToken.None);
            Assert.Equal(2, initial.Keywords.Count);
            Assert.Equal("router", initial.Keywords[0].Word);
            Assert.Single(initial.Feeds);
            Assert.Equal("Example", initial.Feeds[0].Name);
            var updated = await store.UpdateKeywordWeightAsync(initial.Keywords[0].Id, 70, CancellationToken.None);
            Assert.Equal((int?)70, updated?.Weight);
            Assert.Null(await store.UpdateKeywordWeightAsync(999, 20, CancellationToken.None));

            await store.DeleteKeywordAsync(initial.Keywords[1].Id, CancellationToken.None);
            await store.DeleteFeedAsync(initial.Feeds[0].Id, CancellationToken.None);
            var afterDelete = await store.GetCatalogAsync(CancellationToken.None);
            Assert.Single(afterDelete.Keywords);
            Assert.Equal((int?)70, afterDelete.Keywords[0].Weight);
            Assert.Empty(afterDelete.Feeds);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
