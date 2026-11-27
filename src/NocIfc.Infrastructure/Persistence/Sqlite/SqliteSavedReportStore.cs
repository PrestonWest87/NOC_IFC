using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Domain.Reporting;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteSavedReportStore(SqliteConnectionFactory connections) : ISavedReportStore
{
    public async Task<IReadOnlyList<SavedReportEntry>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, title, author, content, created_at
            FROM saved_reports
            ORDER BY created_at DESC
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var reports = new List<SavedReportEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            reports.Add(new SavedReportEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2),
                ReadString(reader, 3), ReadDateTime(reader, 4)));
        }
        return reports;
    }

    public async Task SaveAsync(
        string title,
        string author,
        string content,
        DateTime createdAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO saved_reports (title, author, content, created_at)
            VALUES ($title, $author, $content, $created_at)
            """;
        command.Parameters.AddWithValue("$title", title);
        command.Parameters.AddWithValue("$author", author);
        command.Parameters.AddWithValue("$content", content);
        command.Parameters.AddWithValue("$created_at", FormatDate(createdAtUtc));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task DeleteAsync(int reportId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM saved_reports WHERE id = $id";
        command.Parameters.AddWithValue("$id", reportId);
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
