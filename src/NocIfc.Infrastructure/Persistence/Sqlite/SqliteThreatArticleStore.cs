using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteThreatArticleStore(SqliteConnectionFactory connections) : IThreatArticleStore
{
    internal const string ArticleColumns = """
        id, title, link, summary, published_date, source, score, category, keywords_found,
        is_bubbled, story_group, full_content, ai_bluf, is_pinned, ingested_at,
        enrichment_status, enrichment_attempts, last_enrichment_error, last_enriched_at
        """;

    public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) =>
        GetArticleListAsync(
            "WHERE is_pinned = 1 ORDER BY published_date DESC",
            [],
            cancellationToken);

    public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(
        int limit,
        DateTime publishedAfterUtc,
        CancellationToken cancellationToken) =>
        GetArticleListAsync(
            "WHERE published_date >= $published_after AND score >= 50.0 AND is_pinned = 0 ORDER BY score DESC LIMIT $limit",
            [
                ("$published_after", FormatDate(publishedAfterUtc)),
                ("$limit", limit),
            ],
            cancellationToken);

    public async Task<ThreatArticlePage> GetPageAsync(
        string category,
        string categoryFilter,
        int page,
        int pageSize,
        string? searchTerm,
        int minimumScore,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);

        int total;
        await using (var count = connection.CreateCommand())
        {
            count.CommandText = $"SELECT COUNT(*) FROM articles{BuildFilters(count, category, categoryFilter, searchTerm, minimumScore)}";
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }
        var totalPages = Math.Max(1, (total + pageSize - 1) / pageSize);
        var currentPage = Math.Min(Math.Max(1, page), totalPages);
        var offset = (currentPage - 1) * pageSize;

        var items = new List<ThreatArticle>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"SELECT {ArticleColumns} FROM articles{BuildFilters(command, category, categoryFilter, searchTerm, minimumScore)} {OrderBy(category)} LIMIT $limit OFFSET $offset";
            command.Parameters.AddWithValue("$limit", pageSize);
            command.Parameters.AddWithValue("$offset", offset);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                items.Add(ReadArticle(reader));
            }
        }
        return new ThreatArticlePage(items, total, totalPages, currentPage);
    }

    public async Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        ThreatArticle article;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"SELECT {ArticleColumns} FROM articles WHERE id = $id LIMIT 1";
            command.Parameters.AddWithValue("$id", articleId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }
            article = ReadArticle(reader);
        }

        var weights = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT word, weight FROM keywords";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var word = ReadString(reader, 0);
                if (word is not null)
                {
                    weights[word] = reader.IsDBNull(1) ? 0 : reader.GetInt32(1);
                }
            }
        }

        var matchedKeywords = new List<ThreatArticleKeyword>();
        var totalKeywordScore = 0;
        foreach (var word in article.KeywordsFound ?? [])
        {
            var weight = weights.GetValueOrDefault(word, 0);
            matchedKeywords.Add(new ThreatArticleKeyword(word, weight));
            totalKeywordScore += weight;
        }

        var iocs = new List<ThreatArticleIoc>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT indicator_type, indicator_value, context FROM extracted_iocs WHERE article_id = $article_id";
            command.Parameters.AddWithValue("$article_id", article.Id);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                iocs.Add(new ThreatArticleIoc(
                    ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2)));
            }
        }
        return new ThreatArticleDetail(article, matchedKeywords, totalKeywordScore, iocs);
    }

    public async Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(
        IReadOnlyList<int> articleIds,
        CancellationToken cancellationToken)
    {
        if (articleIds.Count == 0)
        {
            return [];
        }
        if (articleIds.Count > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(articleIds), "At most 100 article IDs are allowed.");
        }

        var ids = articleIds.Distinct().ToArray();
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var parameters = ids.Select((id, index) =>
        {
            var name = $"$id{index}";
            command.Parameters.AddWithValue(name, id);
            return name;
        });
        command.CommandText = $"SELECT {ArticleColumns} FROM articles WHERE id IN ({string.Join(", ", parameters)}) ORDER BY id";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var articles = new List<ThreatArticle>();
        while (await reader.ReadAsync(cancellationToken))
        {
            articles.Add(ReadArticle(reader));
        }
        return articles;
    }

    public async Task TogglePinAsync(int articleId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE articles SET is_pinned = CASE WHEN is_pinned = 1 THEN 0 ELSE 1 END WHERE id = $id";
        command.Parameters.AddWithValue("$id", articleId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE articles SET score = MIN(100.0, score + $amount) WHERE id = $id";
        command.Parameters.AddWithValue("$amount", amount);
        command.Parameters.AddWithValue("$id", articleId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string BuildFilters(
        SqliteCommand command,
        string category,
        string categoryFilter,
        string? searchTerm,
        int minimumScore)
    {
        var filters = new List<string>();
        if (category == "pinned")
        {
            filters.Add("is_pinned = 1");
        }
        else if (category == "live")
        {
            filters.Add("score >= 50.0 AND is_pinned = 0");
        }
        else if (category == "low")
        {
            filters.Add("score < 50.0 AND is_pinned = 0");
        }

        if (categoryFilter != "All")
        {
            filters.Add("category = $category_filter");
            command.Parameters.AddWithValue("$category_filter", categoryFilter);
        }
        if (!string.IsNullOrEmpty(searchTerm))
        {
            filters.Add("(title LIKE $search OR summary LIKE $search)");
            command.Parameters.AddWithValue("$search", $"%{searchTerm}%");
        }
        filters.Add("score >= $minimum_score");
        command.Parameters.AddWithValue("$minimum_score", minimumScore);
        return filters.Count == 0 ? "" : $" WHERE {string.Join(" AND ", filters)}";
    }

    private static string OrderBy(string category) => category is "pinned" or "live" or "low"
        ? "ORDER BY published_date DESC"
        : "ORDER BY score DESC, published_date DESC";

    private async Task<IReadOnlyList<ThreatArticle>> GetArticleListAsync(
        string filterAndOrder,
        IReadOnlyList<(string Name, object Value)> parameters,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {ArticleColumns} FROM articles {filterAndOrder}";
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value);
        }
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var articles = new List<ThreatArticle>();
        while (await reader.ReadAsync(cancellationToken))
        {
            articles.Add(ReadArticle(reader));
        }
        return articles;
    }

    internal static ThreatArticle ReadArticle(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        ReadString(reader, 1),
        ReadString(reader, 2),
        ReadString(reader, 3),
        ReadDateTime(reader, 4),
        ReadString(reader, 5),
        reader.IsDBNull(6) ? null : reader.GetDouble(6),
        ReadString(reader, 7),
        ReadKeywords(reader, 8),
        reader.IsDBNull(9) ? null : reader.GetBoolean(9),
        ReadString(reader, 10),
        ReadString(reader, 11),
        ReadString(reader, 12),
        reader.IsDBNull(13) ? null : reader.GetBoolean(13),
        ReadDateTime(reader, 14),
        ReadString(reader, 15),
        reader.IsDBNull(16) ? null : reader.GetInt32(16),
        ReadString(reader, 17),
        ReadDateTime(reader, 18));

    private static IReadOnlyList<string>? ReadKeywords(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : JsonSerializer.Deserialize<string[]>(reader.GetString(ordinal)) ?? [];

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
