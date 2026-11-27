using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Domain.Reporting;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteDailyBriefingStore(SqliteConnectionFactory connections) : IDailyBriefingStore
{
    public async Task<IReadOnlyList<DailyBriefingEntry>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, report_date, content, created_at
            FROM daily_briefings
            ORDER BY report_date DESC
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var briefings = new List<DailyBriefingEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            briefings.Add(new DailyBriefingEntry(
                reader.GetInt32(0), ReadDateTime(reader, 1), ReadString(reader, 2), ReadDateTime(reader, 3)));
        }
        return briefings;
    }

    public async Task<DailyFusionInputs> GetGenerationInputsAsync(
        DateTime startUtc,
        DateTime endUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);

        var articles = new List<NocIfc.Domain.Threat.ThreatArticle>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = $"""
                SELECT {SqliteThreatArticleStore.ArticleColumns}
                FROM articles
                WHERE published_date >= $start AND published_date < $end AND score >= 80.0
                LIMIT 15
                """;
            command.Parameters.AddWithValue("$start", FormatDate(startUtc));
            command.Parameters.AddWithValue("$end", FormatDate(endUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                articles.Add(SqliteThreatArticleStore.ReadArticle(reader));
            }
        }

        var cves = new List<NocIfc.Domain.Threat.CisaKevEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT id, cve_id, vendor, product, vulnerability_name, date_added,
                       description, required_action, due_date
                FROM cve_items
                WHERE date_added >= $start AND date_added < $end
                LIMIT 20
                """;
            command.Parameters.AddWithValue("$start", FormatDate(startUtc));
            command.Parameters.AddWithValue("$end", FormatDate(endUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                cves.Add(new NocIfc.Domain.Threat.CisaKevEntry(
                    reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2),
                    ReadString(reader, 3), ReadString(reader, 4), ReadDateTime(reader, 5),
                    ReadString(reader, 6), ReadString(reader, 7), ReadString(reader, 8)));
            }
        }

        var hazards = new List<DailyFusionHazard>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT severity, title, location
                FROM regional_hazards
                WHERE updated_at >= $start AND updated_at < $end AND status = 'active'
                  AND (expires_at IS NULL OR julianday(expires_at) > julianday($now))
                  AND (effective_at IS NULL OR julianday(effective_at) <= julianday($now))
                LIMIT 15
                """;
            command.Parameters.AddWithValue("$start", FormatDate(startUtc));
            command.Parameters.AddWithValue("$end", FormatDate(endUtc));
            command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                hazards.Add(new DailyFusionHazard(ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2)));
            }
        }

        var clouds = new List<DailyFusionCloudOutage>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT provider, service, title
                FROM cloud_outages
                WHERE updated_at >= $start AND updated_at < $end
                LIMIT 15
                """;
            command.Parameters.AddWithValue("$start", FormatDate(startUtc));
            command.Parameters.AddWithValue("$end", FormatDate(endUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                clouds.Add(new DailyFusionCloudOutage(ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2)));
            }
        }
        return new DailyFusionInputs(articles, cves, hazards, clouds);
    }

    public async Task SaveAsync(
        DateTime reportDateLocal,
        string content,
        DateTime createdAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO daily_briefings (report_date, content, created_at)
            VALUES ($report_date, $content, $created_at)
            ON CONFLICT(report_date) DO UPDATE SET
                content = excluded.content,
                created_at = excluded.created_at
            """;
        command.Parameters.AddWithValue("$report_date", FormatDate(reportDateLocal));
        command.Parameters.AddWithValue("$content", content);
        command.Parameters.AddWithValue("$created_at", FormatDate(createdAtUtc));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string FormatDate(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Unspecified)
            .ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
}
