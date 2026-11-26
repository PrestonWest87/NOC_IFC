using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteCisaKevStore(SqliteConnectionFactory connections) : ICisaKevStore
{
    public async Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(
        int limit,
        DateTime addedAfterUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, cve_id, vendor, product, vulnerability_name, date_added,
                   description, required_action, due_date
            FROM cve_items
            WHERE date_added >= $added_after
            ORDER BY date_added DESC
            LIMIT $limit
            """;
        command.Parameters.AddWithValue(
            "$added_after",
            addedAfterUtc.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
        command.Parameters.AddWithValue("$limit", limit);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var entries = new List<CisaKevEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            entries.Add(new CisaKevEntry(
                reader.GetInt32(0),
                ReadString(reader, 1),
                ReadString(reader, 2),
                ReadString(reader, 3),
                ReadString(reader, 4),
                ReadDateTime(reader, 5),
                ReadString(reader, 6),
                ReadString(reader, 7),
                ReadString(reader, 8)));
        }
        return entries;
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        var value = reader.GetDateTime(ordinal);
        return DateTime.SpecifyKind(value, DateTimeKind.Unspecified);
    }
}
