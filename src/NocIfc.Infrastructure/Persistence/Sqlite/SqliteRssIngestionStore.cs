using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRssIngestionStore(SqliteConnectionFactory connections) : IRssIngestionStore
{
    public async Task<IReadOnlyList<string>> GetRecentLinksAsync(
        DateTime publishedAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT link FROM articles WHERE published_date >= $published_after AND link IS NOT NULL";
        command.Parameters.AddWithValue("$published_after", FormatDate(publishedAfterUtc));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var links = new List<string>();
        while (await reader.ReadAsync(cancellationToken)) links.Add(reader.GetString(0));
        return links;
    }

    public async Task<int> InsertArticlesAsync(
        IReadOnlyList<RssArticleIngestCandidate> articles,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var added = 0;
        var ingestedAt = DateTime.UtcNow;
        foreach (var article in articles)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO articles (
                    title, link, summary, published_date, source, score, category, keywords_found,
                    is_bubbled, full_content, is_pinned, ingested_at, enrichment_status, enrichment_attempts
                ) VALUES (
                    $title, $link, $summary, $published_date, $source, $score, $category, $keywords,
                    $is_bubbled, NULL, 0, $ingested_at, $enrichment_status, 0
                )
                """;
            AddNullable(insert, "$title", article.Title);
            insert.Parameters.AddWithValue("$link", article.Link);
            AddNullable(insert, "$summary", article.Summary);
            insert.Parameters.AddWithValue("$published_date", FormatDate(article.PublishedDateUtc));
            AddNullable(insert, "$source", article.Source);
            insert.Parameters.AddWithValue("$score", article.Score);
            insert.Parameters.AddWithValue("$category", article.Category);
            insert.Parameters.AddWithValue("$keywords", JsonSerializer.Serialize(article.KeywordsFound));
            insert.Parameters.AddWithValue("$is_bubbled", article.IsBubbled);
            insert.Parameters.AddWithValue("$ingested_at", FormatDate(ingestedAt));
            insert.Parameters.AddWithValue("$enrichment_status", article.Score >= 40 ? "pending" : "enriched");
            if (await insert.ExecuteNonQueryAsync(cancellationToken) == 0) continue;

            await using var idCommand = connection.CreateCommand();
            idCommand.Transaction = transaction;
            idCommand.CommandText = "SELECT last_insert_rowid()";
            var articleId = Convert.ToInt32(await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            foreach (var ioc in article.Iocs)
            {
                await using var insertIoc = connection.CreateCommand();
                insertIoc.Transaction = transaction;
                insertIoc.CommandText = """
                    INSERT INTO extracted_iocs (article_id, indicator_type, indicator_value, context, detected_at)
                    VALUES ($article_id, $type, $indicator, $context, $detected_at)
                    """;
                insertIoc.Parameters.AddWithValue("$article_id", articleId);
                insertIoc.Parameters.AddWithValue("$type", ioc.Type);
                insertIoc.Parameters.AddWithValue("$indicator", ioc.Indicator);
                insertIoc.Parameters.AddWithValue("$context", ioc.Context);
                insertIoc.Parameters.AddWithValue("$detected_at", FormatDate(ingestedAt));
                await insertIoc.ExecuteNonQueryAsync(cancellationToken);
            }
            added++;
        }
        transaction.Commit();
        return added;
    }

    public async Task<int> DeduplicateRecentArticlesAsync(
        DateTime publishedAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var headers = new List<ArticleHeader>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT id, title, link, source, published_date
                FROM articles
                WHERE published_date >= $published_after
                ORDER BY id
                """;
            command.Parameters.AddWithValue("$published_after", FormatDate(publishedAfterUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                headers.Add(new ArticleHeader(
                    reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3), ReadDateTime(reader, 4)));
            }
        }

        var duplicates = new HashSet<int>();
        var seenLinks = new HashSet<string>(StringComparer.Ordinal);
        foreach (var article in headers)
        {
            if (article.Link is not null && !seenLinks.Add(article.Link)) duplicates.Add(article.Id);
        }

        var buckets = new Dictionary<(string Domain, string Hour, int LengthBucket), List<ArticleHeader>>();
        foreach (var article in headers)
        {
            if (duplicates.Contains(article.Id)) continue;
            var title = (article.Title ?? "").Trim().ToLowerInvariant();
            if (title.Length == 0) continue;
            var domain = Uri.TryCreate(article.Link, UriKind.Absolute, out var uri)
                ? uri.Authority
                : article.Source ?? "";
            var hour = (article.PublishedDate ?? DateTime.UtcNow).ToString("yyyyMMddHH", CultureInfo.InvariantCulture);
            var key = (domain, hour, title.Length / 20);
            if (!buckets.TryGetValue(key, out var bucket)) buckets[key] = bucket = [];
            bucket.Add(article with { Title = title });
        }

        foreach (var bucket in buckets.Values)
        {
            var remaining = bucket.ToArray();
            for (var first = 0; first < remaining.Length; first++)
            {
                if (remaining[first] is not { } left) continue;
                var leftTitle = left.Title ?? "";
                for (var next = first + 1; next < remaining.Length; next++)
                {
                    if (remaining[next] is not { } right) continue;
                    if (TitleRatio(leftTitle, right.Title ?? "") <= 85) continue;
                    duplicates.Add(right.Id);
                    remaining[next] = null!;
                }
            }
        }
        if (duplicates.Count == 0) return 0;

        using var transaction = connection.BeginTransaction();
        foreach (var chunk in duplicates.Chunk(500))
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            var parameters = chunk.Select((_, index) => $"$id{index}").ToArray();
            command.CommandText = $"DELETE FROM articles WHERE id IN ({string.Join(", ", parameters)})";
            for (var index = 0; index < chunk.Length; index++) command.Parameters.AddWithValue(parameters[index], chunk[index]);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return duplicates.Count;
    }

    private static double TitleRatio(string first, string second)
    {
        var totalLength = first.Length + second.Length;
        if (totalLength == 0) return 100;
        // shortcut: titles over 4096 characters deduplicate only when identical; use a bounded similarity library if such titles become common.
        if (first.Length > 4096 || second.Length > 4096)
        {
            return string.Equals(first, second, StringComparison.Ordinal) ? 100 : 0;
        }
        if (2.0 * Math.Min(first.Length, second.Length) / totalLength * 100 <= 85) return 0;
        var previous = new int[second.Length + 1];
        var current = new int[second.Length + 1];
        foreach (var left in first)
        {
            current[0] = 0;
            for (var index = 0; index < second.Length; index++)
            {
                current[index + 1] = left == second[index]
                    ? previous[index] + 1
                    : Math.Max(current[index], previous[index + 1]);
            }
            (previous, current) = (current, previous);
        }
        return 200.0 * previous[^1] / totalLength;
    }

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private sealed record ArticleHeader(int Id, string? Title, string? Link, string? Source, DateTime? PublishedDate);
}
