using System.Globalization;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteUserDirectory(SqliteConnectionFactory connections) : IUserDirectory
{
    public async Task<IReadOnlyList<UserDirectoryEntry>> GetAllAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);

        var pendingInvites = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var inviteCommand = connection.CreateCommand())
        {
            inviteCommand.CommandText = """
                SELECT username
                FROM registration_invites
                WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > $now
                """;
            inviteCommand.Parameters.AddWithValue(
                "$now",
                DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
            await using var inviteReader = await inviteCommand.ExecuteReaderAsync(cancellationToken);
            while (await inviteReader.ReadAsync(cancellationToken))
            {
                if (!inviteReader.IsDBNull(0))
                {
                    pendingInvites.Add(inviteReader.GetString(0));
                }
            }
        }

        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT u.id, u.username, u.full_name, u.job_title, u.contact_info, u.email,
                   u.email_verified_at, COALESCE(NULLIF(u.account_type, ''), 'individual'),
                   u.role, u.is_active, u.created_at, u.last_login_at, u.last_activity_at,
                   ecr.status, ecr.requested_email
            FROM users AS u
            LEFT JOIN email_change_requests AS ecr ON ecr.id = (
                SELECT MAX(candidate.id)
                FROM email_change_requests AS candidate
                WHERE candidate.user_id = u.id
                  AND candidate.status IN ('pending_review', 'pending_verification')
            )
            ORDER BY u.username ASC
            """;

        var users = new List<UserDirectoryEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var email = ReadNullableString(reader, 5);
            var emailVerified = !reader.IsDBNull(6);
            var accountType = reader.GetString(7);
            var pendingStatus = ReadNullableString(reader, 13);
            var pendingEmail = ReadNullableString(reader, 14);
            var emailStatus = pendingStatus switch
            {
                "pending_review" => "pending_approval",
                "pending_verification" => "pending_verification",
                _ when emailVerified => "verified",
                _ when accountType == "display" && string.IsNullOrEmpty(email) => "exempt",
                _ when string.IsNullOrEmpty(email) => "missing",
                _ => "unverified",
            };

            users.Add(new UserDirectoryEntry(
                reader.GetInt32(0),
                reader.GetString(1),
                ReadNullableString(reader, 2),
                ReadNullableString(reader, 3),
                ReadNullableString(reader, 4),
                email,
                emailVerified,
                emailStatus,
                pendingEmail,
                accountType,
                ReadNullableString(reader, 8),
                reader.GetBoolean(9),
                ReadNullableDateTime(reader, 10),
                ReadNullableDateTime(reader, 11),
                ReadNullableDateTime(reader, 12),
                pendingInvites.Contains(reader.GetString(1))));
        }

        return users;
    }

    private static string? ReadNullableString(Microsoft.Data.Sqlite.SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadNullableDateTime(Microsoft.Data.Sqlite.SqliteDataReader reader, int ordinal)
    {
        var value = ReadNullableString(reader, ordinal);
        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
            ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified)
            : null;
    }
}
