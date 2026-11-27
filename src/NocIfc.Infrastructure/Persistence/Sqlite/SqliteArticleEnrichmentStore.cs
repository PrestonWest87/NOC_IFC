using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteArticleEnrichmentStore(SqliteConnectionFactory connections) : IArticleEnrichmentStore
{
    public async Task<IReadOnlyList<ArticleEnrichmentCandidate>> ClaimPendingAsync(
        int limit,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit));
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var candidates = new List<ArticleEnrichmentCandidate>();
        await using (var select = connection.CreateCommand())
        {
            select.Transaction = transaction;
            select.CommandText = """
                SELECT id, link
                FROM articles
                WHERE enrichment_status IN ('pending', 'failed')
                  AND COALESCE(enrichment_attempts, 0) < 3
                  AND score >= 40
                  AND link IS NOT NULL AND link != ''
                ORDER BY score DESC, ingested_at ASC
                LIMIT $limit
                """;
            select.Parameters.AddWithValue("$limit", limit);
            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                candidates.Add(new ArticleEnrichmentCandidate(reader.GetInt32(0), reader.GetString(1)));
            }
        }
        foreach (var candidate in candidates)
        {
            await using var update = connection.CreateCommand();
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE articles
                SET enrichment_status = 'content_pending',
                    enrichment_attempts = COALESCE(enrichment_attempts, 0) + 1
                WHERE id = $id AND enrichment_status IN ('pending', 'failed')
                """;
            update.Parameters.AddWithValue("$id", candidate.Id);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return candidates;
    }

    public async Task SaveEnrichedAsync(
        int articleId,
        string fullContent,
        DateTime enrichedAtUtc,
        CancellationToken cancellationToken)
    {
        if (fullContent.Length > 200_000) throw new ArgumentException("Article content exceeds the storage limit.");
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE articles
            SET full_content = $content,
                enrichment_status = 'enriched',
                last_enriched_at = $enriched_at,
                last_enrichment_error = NULL
            WHERE id = $id
            """;
        command.Parameters.AddWithValue("$content", fullContent);
        command.Parameters.AddWithValue("$enriched_at", FormatDate(enrichedAtUtc));
        command.Parameters.AddWithValue("$id", articleId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SaveFailureAsync(int articleId, string error, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE articles
            SET enrichment_status = 'failed', last_enrichment_error = $error
            WHERE id = $id
            """;
        command.Parameters.AddWithValue("$error", error[..Math.Min(error.Length, 500)]);
        command.Parameters.AddWithValue("$id", articleId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
