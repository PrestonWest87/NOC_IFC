using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteFailedLoginAlertStore(SqliteConnectionFactory connections) : IFailedLoginAlertStore
{
    public async Task<FailedLoginAlert?> RecordAsync(
        string? username,
        string? sourceIp,
        CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        var config = await ReadConfigAsync(connection, transaction, cancellationToken);
        if (config is null || !config.Enabled)
        {
            return null;
        }

        string recipients;
        try
        {
            recipients = EmailAddressRules.NormalizeRecipients(config.Recipients);
        }
        catch (ArgumentException)
        {
            return null;
        }
        if (recipients.Length == 0)
        {
            return null;
        }

        var threshold = Math.Clamp(config.Threshold == 0 ? 5 : config.Threshold, 2, 100);
        var windowMinutes = Math.Clamp(config.WindowMinutes == 0 ? 5 : config.WindowMinutes, 1, 60);
        var safeUsername = SanitizeUsername(username);
        var safeSourceIp = IPAddress.TryParse(sourceIp, out var parsedIp) ? parsedIp.ToString() : null;
        var windowCutoff = now.AddMinutes(-windowMinutes);

        await using (var cleanup = connection.CreateCommand())
        {
            cleanup.Transaction = transaction;
            cleanup.CommandText = "DELETE FROM failed_login_attempts WHERE attempted_at < $cutoff";
            cleanup.Parameters.AddWithValue("$cutoff", FormatDatabaseDate(now.AddHours(-24)));
            await cleanup.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO failed_login_attempts (username, source_ip, attempted_at) VALUES ($username, $source_ip, $now)";
            insert.Parameters.AddWithValue("$username", safeUsername);
            insert.Parameters.AddWithValue("$source_ip", (object?)safeSourceIp ?? DBNull.Value);
            insert.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        var attempts = await ReadRecentAttemptsAsync(connection, transaction, windowCutoff, cancellationToken);
        if (attempts.Count < threshold)
        {
            transaction.Commit();
            return null;
        }

        await using (var claim = connection.CreateCommand())
        {
            claim.Transaction = transaction;
            claim.CommandText = """
                UPDATE system_config
                SET failed_login_alert_last_sent = $now
                WHERE id = $config_id AND failed_login_alert_enabled = 1
                  AND (failed_login_alert_last_sent IS NULL OR failed_login_alert_last_sent <= $cutoff)
                """;
            claim.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            claim.Parameters.AddWithValue("$config_id", config.Id);
            claim.Parameters.AddWithValue("$cutoff", FormatDatabaseDate(windowCutoff));
            if (await claim.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                transaction.Commit();
                return null;
            }
        }

        transaction.Commit();
        return new FailedLoginAlert(recipients, threshold, windowMinutes, now, attempts);
    }

    private static async Task<AlertConfig?> ReadConfigAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT id, failed_login_alert_enabled, failed_login_alert_recipients,
                   failed_login_alert_threshold, failed_login_alert_window_minutes
            FROM system_config
            ORDER BY id
            LIMIT 1
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }
        return new AlertConfig(
            reader.GetInt32(0),
            reader.GetBoolean(1),
            reader.IsDBNull(2) ? "" : reader.GetString(2),
            reader.IsDBNull(3) ? 5 : reader.GetInt32(3),
            reader.IsDBNull(4) ? 5 : reader.GetInt32(4));
    }

    private static async Task<IReadOnlyList<FailedLoginAttemptEntry>> ReadRecentAttemptsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        DateTime cutoff,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT username, source_ip, attempted_at
            FROM failed_login_attempts
            WHERE attempted_at >= $cutoff
            ORDER BY attempted_at ASC, id ASC
            """;
        command.Parameters.AddWithValue("$cutoff", FormatDatabaseDate(cutoff));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var attempts = new List<FailedLoginAttemptEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var attemptedAt = DateTime.Parse(reader.GetString(2), CultureInfo.InvariantCulture, DateTimeStyles.None);
            attempts.Add(new FailedLoginAttemptEntry(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                DateTime.SpecifyKind(attemptedAt, DateTimeKind.Unspecified)));
        }
        return attempts;
    }

    private static string SanitizeUsername(string? value)
    {
        var result = new StringBuilder();
        foreach (var rune in (value ?? "").EnumerateRunes().Take(128))
        {
            var category = Rune.GetUnicodeCategory(rune);
            result.Append(category is UnicodeCategory.Control
                or UnicodeCategory.Format
                or UnicodeCategory.Surrogate
                or UnicodeCategory.PrivateUse
                or UnicodeCategory.OtherNotAssigned
                or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator
                    ? " "
                    : rune.ToString());
        }
        return result.Length == 0 ? "(blank)" : result.ToString();
    }

    private static string FormatDatabaseDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private sealed record AlertConfig(int Id, bool Enabled, string Recipients, int Threshold, int WindowMinutes);
}
