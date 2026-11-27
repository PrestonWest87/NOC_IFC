using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAiopsSitrepActionStore(SqliteConnectionFactory connections) : IAiopsSitrepActionStore
{
    public async Task<AiopsRollingBriefInputs> GetRollingBriefInputsAsync(
        DateTime sinceUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);

        var articles = new List<string?>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT title
                FROM articles
                WHERE published_date >= $since AND score >= 50
                ORDER BY score DESC
                LIMIT 15
                """;
            command.Parameters.AddWithValue("$since", FormatDate(sinceUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                articles.Add(ReadString(reader, 0));
            }
        }

        var hazards = new List<AiopsRollingBriefHazard>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT severity, title, location, description
                FROM regional_hazards
                WHERE updated_at >= $since AND status = 'active'
                  AND (expires_at IS NULL OR julianday(expires_at) > julianday($now))
                  AND (effective_at IS NULL OR julianday(effective_at) <= julianday($now))
                ORDER BY id
                LIMIT 20
                """;
            command.Parameters.AddWithValue("$since", FormatDate(sinceUtc));
            command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                hazards.Add(new AiopsRollingBriefHazard(
                    ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2), ReadString(reader, 3)));
            }
        }

        var clouds = new List<AiopsRollingBriefCloudOutage>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT provider, service, title
                FROM cloud_outages
                WHERE updated_at >= $since
                ORDER BY id
                LIMIT 15
                """;
            command.Parameters.AddWithValue("$since", FormatDate(sinceUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                clouds.Add(new AiopsRollingBriefCloudOutage(
                    ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2)));
            }
        }

        return new AiopsRollingBriefInputs(articles, hazards, clouds);
    }

    public async Task SaveRollingSummaryAsync(
        string summary,
        DateTime savedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using (var exists = connection.CreateCommand())
        {
            exists.CommandText = "SELECT 1 FROM system_config ORDER BY id LIMIT 1";
            if (await exists.ExecuteScalarAsync(cancellationToken) is null)
            {
                await SqliteApplicationSettingsStore.InsertDefaultsAsync(
                    connection,
                    new GlobalApplicationSettingsUpdate(null, null, null, null, null, null, null),
                    cancellationToken);
            }
        }
        await using var update = connection.CreateCommand();
        update.CommandText = """
            UPDATE system_config
            SET rolling_summary = $summary, rolling_summary_time = $saved_at
            WHERE id = (SELECT id FROM system_config ORDER BY id LIMIT 1)
            """;
        update.Parameters.AddWithValue("$summary", summary);
        update.Parameters.AddWithValue("$saved_at", FormatDate(savedAtUtc));
        await update.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string FormatDate(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Unspecified)
            .ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
