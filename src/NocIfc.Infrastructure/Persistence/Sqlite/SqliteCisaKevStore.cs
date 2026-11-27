using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteCisaKevStore(SqliteConnectionFactory connections) : ICisaKevStore
{
    public async Task<int> InsertMissingAsync(
        IReadOnlyList<CisaKevEntry> entries,
        CancellationToken cancellationToken)
    {
        var uniqueEntries = entries.Where(entry => !string.IsNullOrEmpty(entry.CveId))
            .GroupBy(entry => entry.CveId!, StringComparer.Ordinal)
            .Select(group => group.First())
            .ToArray();
        if (uniqueEntries.Length == 0) return 0;

        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var existing = new HashSet<string>(StringComparer.Ordinal);
        foreach (var chunk in uniqueEntries.Chunk(500))
        {
            await using var query = connection.CreateCommand();
            query.Transaction = transaction;
            var parameters = chunk.Select((entry, index) => $"$cve{index}").ToArray();
            query.CommandText = $"SELECT cve_id FROM cve_items WHERE cve_id IN ({string.Join(", ", parameters)})";
            for (var index = 0; index < chunk.Length; index++)
            {
                query.Parameters.AddWithValue(parameters[index], chunk[index].CveId!);
            }
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (!reader.IsDBNull(0)) existing.Add(reader.GetString(0));
            }
        }

        var added = 0;
        foreach (var entry in uniqueEntries)
        {
            if (existing.Contains(entry.CveId!)) continue;
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT OR IGNORE INTO cve_items (
                    cve_id, vendor, product, vulnerability_name, date_added,
                    description, required_action, due_date
                ) VALUES (
                    $cve_id, $vendor, $product, $vulnerability_name, $date_added,
                    $description, $required_action, $due_date
                )
                """;
            AddNullable(insert, "$cve_id", entry.CveId);
            AddNullable(insert, "$vendor", entry.Vendor);
            AddNullable(insert, "$product", entry.Product);
            AddNullable(insert, "$vulnerability_name", entry.VulnerabilityName);
            insert.Parameters.AddWithValue("$date_added", FormatDate(entry.DateAdded ?? DateTime.UtcNow));
            AddNullable(insert, "$description", entry.Description);
            AddNullable(insert, "$required_action", entry.RequiredAction);
            AddNullable(insert, "$due_date", entry.DueDate);
            added += await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return added;
    }

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

    private static void AddNullable(SqliteCommand command, string name, string? value) =>
        command.Parameters.AddWithValue(name, (object?)value ?? DBNull.Value);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

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
