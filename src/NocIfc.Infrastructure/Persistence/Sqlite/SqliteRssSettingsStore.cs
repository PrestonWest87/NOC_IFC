using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRssSettingsStore(SqliteConnectionFactory connections) : IRssSettingsStore
{
    public async Task<RssSettingsCatalog> GetCatalogAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var keywords = new List<KeywordDirectoryEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id, word, weight FROM keywords ORDER BY weight DESC";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                keywords.Add(new KeywordDirectoryEntry(
                    reader.GetInt32(0),
                    reader.IsDBNull(1) ? "" : reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetInt32(2)));
            }
        }

        var feeds = new List<FeedSourceEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id, url, name, is_active FROM feed_sources";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                feeds.Add(new FeedSourceEntry(
                    reader.GetInt32(0),
                    ReadString(reader, 1),
                    ReadString(reader, 2),
                    reader.IsDBNull(3) ? null : reader.GetBoolean(3)));
            }
        }
        return new RssSettingsCatalog(keywords, feeds);
    }

    public async Task AddKeywordsAsync(
        IReadOnlyList<KeywordDirectoryEntry> keywords,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        foreach (var keyword in keywords)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT OR IGNORE INTO keywords (word, weight) VALUES ($word, $weight)";
            command.Parameters.AddWithValue("$word", keyword.Word);
            command.Parameters.AddWithValue("$weight", (object?)keyword.Weight ?? DBNull.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    public async Task AddFeedsAsync(IReadOnlyList<FeedSourceEntry> feeds, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        foreach (var feed in feeds)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT OR IGNORE INTO feed_sources (url, name, is_active) VALUES ($url, $name, 1)";
            command.Parameters.AddWithValue("$url", (object?)feed.Url ?? DBNull.Value);
            command.Parameters.AddWithValue("$name", (object?)feed.Name ?? DBNull.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    public async Task<KeywordDirectoryEntry?> UpdateKeywordWeightAsync(
        int keywordId,
        int weight,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE keywords SET weight = $weight WHERE id = $id";
        update.Parameters.AddWithValue("$weight", weight);
        update.Parameters.AddWithValue("$id", keywordId);
        if (await update.ExecuteNonQueryAsync(cancellationToken) == 0)
        {
            return null;
        }

        await using var read = connection.CreateCommand();
        read.Transaction = transaction;
        read.CommandText = "SELECT id, word, weight FROM keywords WHERE id = $id";
        read.Parameters.AddWithValue("$id", keywordId);
        await using var reader = await read.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        var result = new KeywordDirectoryEntry(reader.GetInt32(0), reader.GetString(1), reader.GetInt32(2));
        transaction.Commit();
        return result;
    }

    public Task DeleteKeywordAsync(int keywordId, CancellationToken cancellationToken) =>
        DeleteAsync("keywords", keywordId, cancellationToken);

    public Task DeleteFeedAsync(int feedId, CancellationToken cancellationToken) =>
        DeleteAsync("feed_sources", feedId, cancellationToken);

    private async Task DeleteAsync(string table, int id, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"DELETE FROM {table} WHERE id = $id";
        command.Parameters.AddWithValue("$id", id);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
