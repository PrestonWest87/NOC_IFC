using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Logbook;
using NocIfc.Domain.Logbook;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteShiftLogbookStore(SqliteConnectionFactory connections) : IShiftLogbookStore
{
    public async Task<IReadOnlyList<ShiftLogEntry>> GetEntriesAsync(
        string? roleFilter,
        DateTime? startUtc,
        DateTime? endExclusiveUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, analyst, author_role, shift_date, shift_period, content, created_at, is_deleted
            FROM shift_logs
            WHERE is_deleted = 0
              AND ($role IS NULL OR author_role = $role)
              AND ($start IS NULL OR julianday(created_at) >= julianday($start))
              AND ($end IS NULL OR julianday(created_at) < julianday($end))
            ORDER BY created_at DESC
            """;
        command.Parameters.AddWithValue("$role", (object?)roleFilter ?? DBNull.Value);
        command.Parameters.AddWithValue("$start", (object?)FormatDate(startUtc) ?? DBNull.Value);
        command.Parameters.AddWithValue("$end", (object?)FormatDate(endExclusiveUtc) ?? DBNull.Value);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var entries = new List<ShiftLogEntry>();
        while (await reader.ReadAsync(cancellationToken)) entries.Add(ReadEntry(reader));
        return entries;
    }

    public async Task<IReadOnlyList<string>> GetRoleNamesAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM roles ORDER BY id";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var names = new List<string>();
        while (await reader.ReadAsync(cancellationToken))
        {
            if (!reader.IsDBNull(0)) names.Add(reader.GetString(0));
        }
        return names;
    }

    public async Task<string?> GetUserFullNameAsync(int userId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT full_name FROM users WHERE id = $id";
        command.Parameters.AddWithValue("$id", userId);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public async Task<int> CreateAsync(
        string analyst,
        string authorRole,
        string shiftPeriod,
        string content,
        DateTime createdAtUtc,
        DateTime shiftDateUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO shift_logs(analyst, author_role, shift_date, shift_period, content, created_at, is_deleted)
            VALUES ($analyst, $role, $shiftDate, $period, $content, $createdAt, 0);
            SELECT last_insert_rowid();
            """;
        command.Parameters.AddWithValue("$analyst", analyst);
        command.Parameters.AddWithValue("$role", authorRole);
        command.Parameters.AddWithValue("$shiftDate", FormatDate(shiftDateUtc));
        command.Parameters.AddWithValue("$period", shiftPeriod);
        command.Parameters.AddWithValue("$content", content);
        command.Parameters.AddWithValue("$createdAt", FormatDate(createdAtUtc));
        var id = await command.ExecuteScalarAsync(cancellationToken);
        return Convert.ToInt32(id, CultureInfo.InvariantCulture);
    }

    public async Task<ShiftLogEntry?> GetByIdAsync(int entryId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, analyst, author_role, shift_date, shift_period, content, created_at, is_deleted
            FROM shift_logs WHERE id = $id
            """;
        command.Parameters.AddWithValue("$id", entryId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? ReadEntry(reader) : null;
    }

    public async Task<bool> SetDeletedAsync(int entryId, bool isDeleted, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE shift_logs SET is_deleted = $deleted WHERE id = $id";
        command.Parameters.AddWithValue("$deleted", isDeleted ? 1 : 0);
        command.Parameters.AddWithValue("$id", entryId);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    private static ShiftLogEntry ReadEntry(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        ReadString(reader, 1),
        ReadString(reader, 2),
        ReadDateTime(reader, 3),
        ReadString(reader, 4),
        ReadString(reader, 5),
        ReadDateTime(reader, 6),
        !reader.IsDBNull(7) && reader.GetInt32(7) != 0);

    private static string? FormatDate(DateTime? value) =>
        value?.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal)
            ? null
            : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
}
