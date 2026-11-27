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

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
}
