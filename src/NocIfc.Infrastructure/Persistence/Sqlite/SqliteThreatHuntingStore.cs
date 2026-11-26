using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteThreatHuntingStore(SqliteConnectionFactory connections) : IThreatHuntingStore
{
    public async Task<IReadOnlyList<ExtractedIocEntry>> GetRecentIocsAsync(
        DateTime detectedAfterUtc,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT i.id, i.indicator_type, i.indicator_value, i.context, i.detected_at,
                   a.link, a.title
            FROM extracted_iocs AS i
            LEFT JOIN articles AS a ON a.id = i.article_id
            WHERE i.detected_at >= $detected_after
            ORDER BY i.detected_at DESC, i.id DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$detected_after", FormatDate(detectedAfterUtc));
        command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new List<ExtractedIocEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new ExtractedIocEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3),
                ReadDateTime(reader, 4), ReadString(reader, 5), ReadString(reader, 6)));
        }
        return rows;
    }

    public async Task<IReadOnlyList<ThreatArticle>> SearchArticlesAsync(
        DateTime publishedAfterUtc,
        IReadOnlyList<string> terms,
        int limit,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        var termFilters = new List<string>();
        for (var index = 0; index < terms.Count; index++)
        {
            var parameter = $"$term{index}";
            var escaped = terms[index].Replace("\\", "\\\\", StringComparison.Ordinal)
                .Replace("%", "\\%", StringComparison.Ordinal)
                .Replace("_", "\\_", StringComparison.Ordinal);
            termFilters.Add($"(title LIKE {parameter} ESCAPE '\\' OR summary LIKE {parameter} ESCAPE '\\' OR full_content LIKE {parameter} ESCAPE '\\')");
            command.Parameters.AddWithValue(parameter, $"%{escaped}%");
        }
        command.CommandText = $"""
            SELECT {SqliteThreatArticleStore.ArticleColumns}
            FROM articles
            WHERE published_date >= $published_after AND ({string.Join(" OR ", termFilters)})
            ORDER BY published_date DESC, id DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue("$published_after", FormatDate(publishedAfterUtc));
        command.Parameters.AddWithValue("$limit", limit);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var articles = new List<ThreatArticle>();
        while (await reader.ReadAsync(cancellationToken))
        {
            articles.Add(SqliteThreatArticleStore.ReadArticle(reader));
        }
        return articles;
    }

    public async Task<PagedElasticEvents> GetElasticEventsAsync(
        DateTime createdAfterUtc,
        int page,
        int pageSize,
        int hoursBack,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        int total;
        await using (var count = connection.CreateCommand())
        {
            count.CommandText = "SELECT COUNT(*) FROM elastic_events WHERE timestamp >= $created_after";
            count.Parameters.AddWithValue("$created_after", FormatDate(createdAfterUtc));
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }
        var offset = ((long)page - 1) * pageSize;
        var events = new List<ElasticEventEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT id, timestamp, index_name, severity, message, source_ip, event_category
                FROM elastic_events
                WHERE timestamp >= $created_after
                ORDER BY timestamp DESC, id DESC
                LIMIT $page_size OFFSET $offset
                """;
            command.Parameters.AddWithValue("$created_after", FormatDate(createdAfterUtc));
            command.Parameters.AddWithValue("$page_size", pageSize);
            command.Parameters.AddWithValue("$offset", offset);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                events.Add(new ElasticEventEntry(
                    reader.GetString(0), ReadDateTime(reader, 1), ReadString(reader, 2),
                    ReadString(reader, 3), ReadString(reader, 4), ReadString(reader, 5), ReadString(reader, 6)));
            }
        }
        return new PagedElasticEvents(events, total, page, pageSize, hoursBack);
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
