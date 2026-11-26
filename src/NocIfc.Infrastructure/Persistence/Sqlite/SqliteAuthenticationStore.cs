using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAuthenticationStore(SqliteConnectionFactory connections) : IAuthenticationStore
{
    public async Task<LoginCredential?> FindCredentialsAsync(string username, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, username, password_hash, is_active FROM users WHERE username = $username LIMIT 1";
        command.Parameters.AddWithValue("$username", username);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new LoginCredential(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.GetBoolean(3));
    }

    public async Task<LoginUser?> CreateSessionAsync(
        LoginCredential credential,
        string token,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = """
                UPDATE users
                SET last_login_at = $now, last_activity_at = $now
                WHERE id = $user_id AND is_active = 1 AND password_hash = $password_hash
                """;
            update.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            update.Parameters.AddWithValue("$user_id", credential.Id);
            update.Parameters.AddWithValue("$password_hash", credential.PasswordHash!);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return null;
            }
        }

        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO user_sessions (user_id, token, created_at) VALUES ($user_id, $token, $now)";
            insert.Parameters.AddWithValue("$user_id", credential.Id);
            insert.Parameters.AddWithValue("$token", token);
            insert.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        var user = await ReadUserAsync(connection, transaction, credential.Id, cancellationToken);
        if (user is null)
        {
            return null;
        }
        transaction.Commit();
        return user;
    }

    public async Task<LoginUser?> GetCurrentUserAsync(int userId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        return await ReadUserAsync(connection, null, userId, cancellationToken);
    }

    public async Task RevokeSessionAsync(int userId, string token, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM user_sessions WHERE user_id = $user_id AND token = $token";
            delete.Parameters.AddWithValue("$user_id", userId);
            delete.Parameters.AddWithValue("$token", token);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE users SET session_token = NULL WHERE id = $user_id AND session_token = $token";
            update.Parameters.AddWithValue("$user_id", userId);
            update.Parameters.AddWithValue("$token", token);
            await update.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    public async Task<bool> UpdateThemeAsync(int userId, string theme, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE users SET theme = $theme WHERE id = $user_id AND is_active = 1";
        command.Parameters.AddWithValue("$theme", theme);
        command.Parameters.AddWithValue("$user_id", userId);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<string?> GetPasswordHashAsync(int userId, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT password_hash FROM users WHERE id = $user_id AND is_active = 1 LIMIT 1";
        command.Parameters.AddWithValue("$user_id", userId);
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public async Task<bool> UpdateProfileAsync(
        int userId,
        string fullName,
        string jobTitle,
        string contactInfo,
        string defaultShift,
        string? expectedPasswordHash,
        string? newPasswordHash,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = newPasswordHash is null
            ? """
              UPDATE users SET full_name = $full_name, job_title = $job_title,
                  contact_info = $contact_info, default_shift = $default_shift
              WHERE id = $user_id AND is_active = 1
              """
            : """
              UPDATE users SET full_name = $full_name, job_title = $job_title,
                  contact_info = $contact_info, default_shift = $default_shift, password_hash = $new_hash
              WHERE id = $user_id AND is_active = 1 AND password_hash = $old_hash
              """;
        command.Parameters.AddWithValue("$full_name", fullName);
        command.Parameters.AddWithValue("$job_title", jobTitle);
        command.Parameters.AddWithValue("$contact_info", contactInfo);
        command.Parameters.AddWithValue("$default_shift", defaultShift);
        command.Parameters.AddWithValue("$user_id", userId);
        if (newPasswordHash is not null)
        {
            command.Parameters.AddWithValue("$new_hash", newPasswordHash);
            command.Parameters.AddWithValue("$old_hash", expectedPasswordHash!);
        }
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    public async Task<RegistrationInviteInfo?> GetRegistrationInviteAsync(
        string tokenHash,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT username, role, email, expires_at
            FROM registration_invites
            WHERE token_hash = $token_hash AND used_at IS NULL AND revoked_at IS NULL
              AND expires_at > $now
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$token_hash", tokenHash);
        command.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new RegistrationInviteInfo(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            DateTime.SpecifyKind(DateTime.Parse(reader.GetString(3), CultureInfo.InvariantCulture), DateTimeKind.Unspecified));
    }

    public async Task<LoginUser?> CompleteRegistrationAsync(
        string tokenHash,
        string passwordHash,
        string fullName,
        string jobTitle,
        string contactInfo,
        string defaultShift,
        string theme,
        string sessionToken,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        int inviteId;
        string username;
        string role;
        string email;
        string emailNormalized;

        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = transaction;
            lookup.CommandText = """
                SELECT id, username, role, email, email_normalized
                FROM registration_invites
                WHERE token_hash = $token_hash AND used_at IS NULL AND revoked_at IS NULL
                  AND expires_at > $now
                LIMIT 1
                """;
            lookup.Parameters.AddWithValue("$token_hash", tokenHash);
            lookup.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return null;
            }
            inviteId = reader.GetInt32(0);
            username = reader.GetString(1);
            role = reader.GetString(2);
            email = reader.GetString(3);
            emailNormalized = reader.GetString(4);
        }

        await using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText = "SELECT 1 FROM users WHERE username = $username LIMIT 1";
            existing.Parameters.AddWithValue("$username", username);
            if (await existing.ExecuteScalarAsync(cancellationToken) is not null)
            {
                await using var consume = connection.CreateCommand();
                consume.Transaction = transaction;
                consume.CommandText = "UPDATE registration_invites SET used_at = $now WHERE id = $invite_id";
                consume.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
                consume.Parameters.AddWithValue("$invite_id", inviteId);
                await consume.ExecuteNonQueryAsync(cancellationToken);
                transaction.Commit();
                throw new RegistrationException("That registration has already been completed.");
            }
        }

        await using (var consume = connection.CreateCommand())
        {
            consume.Transaction = transaction;
            consume.CommandText = """
                UPDATE registration_invites SET used_at = $now
                WHERE id = $invite_id AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $now
                """;
            consume.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            consume.Parameters.AddWithValue("$invite_id", inviteId);
            if (await consume.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return null;
            }
        }

        int userId;
        await using (var createUser = connection.CreateCommand())
        {
            createUser.Transaction = transaction;
            createUser.CommandText = """
                INSERT INTO users (
                    username, password_hash, role, session_token, full_name, job_title,
                    contact_info, default_shift, theme, account_type, email, email_normalized,
                    email_verified_at, is_active, created_at, last_login_at, last_activity_at
                ) VALUES (
                    $username, $password_hash, $role, $session_token, $full_name, $job_title,
                    $contact_info, $default_shift, $theme, 'individual', $email, $email_normalized,
                    $now, 1, $now, $now, $now
                )
                """;
            createUser.Parameters.AddWithValue("$username", username);
            createUser.Parameters.AddWithValue("$password_hash", passwordHash);
            createUser.Parameters.AddWithValue("$role", role);
            createUser.Parameters.AddWithValue("$session_token", sessionToken);
            createUser.Parameters.AddWithValue("$full_name", fullName);
            createUser.Parameters.AddWithValue("$job_title", jobTitle);
            createUser.Parameters.AddWithValue("$contact_info", contactInfo);
            createUser.Parameters.AddWithValue("$default_shift", defaultShift);
            createUser.Parameters.AddWithValue("$theme", theme);
            createUser.Parameters.AddWithValue("$email", email);
            createUser.Parameters.AddWithValue("$email_normalized", emailNormalized);
            createUser.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            await createUser.ExecuteNonQueryAsync(cancellationToken);
            await using var idCommand = connection.CreateCommand();
            idCommand.Transaction = transaction;
            idCommand.CommandText = "SELECT last_insert_rowid()";
            userId = Convert.ToInt32(await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        await using (var createSession = connection.CreateCommand())
        {
            createSession.Transaction = transaction;
            createSession.CommandText = "INSERT INTO user_sessions (user_id, token, created_at) VALUES ($user_id, $token, $now)";
            createSession.Parameters.AddWithValue("$user_id", userId);
            createSession.Parameters.AddWithValue("$token", sessionToken);
            createSession.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            await createSession.ExecuteNonQueryAsync(cancellationToken);
        }

        var user = await ReadUserAsync(connection, transaction, userId, cancellationToken);
        if (user is null)
        {
            return null;
        }
        transaction.Commit();
        return user;
    }

    private static async Task<LoginUser?> ReadUserAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        int userId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT u.id, u.username, u.role, u.full_name, u.job_title, u.contact_info,
                   u.default_shift, u.theme, COALESCE(NULLIF(u.account_type, ''), 'individual'),
                   u.email, u.email_normalized, u.email_verified_at, u.is_active,
                   u.created_at, u.last_login_at, u.last_activity_at,
                   ecr.status, ecr.requested_email,
                   r.allowed_pages, r.allowed_actions, r.allowed_site_types
            FROM users AS u
            LEFT JOIN roles AS r ON lower(r.name) = lower(COALESCE(NULLIF(u.role, ''), 'analyst'))
            LEFT JOIN email_change_requests AS ecr ON ecr.id = (
                SELECT candidate.id
                FROM email_change_requests AS candidate
                WHERE candidate.user_id = u.id
                  AND candidate.status IN ('pending_review', 'pending_verification')
                ORDER BY candidate.requested_at DESC, candidate.id DESC
                LIMIT 1
            )
            WHERE u.id = $user_id AND u.is_active = 1
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$user_id", userId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        var accountType = reader.GetString(8);
        var email = NullableString(reader, 9);
        var emailVerifiedAt = NullableDateTime(reader, 11);
        var pendingStatus = NullableString(reader, 16);
        var recoveryStatus = accountType == "display"
            ? "exempt"
            : pendingStatus switch
            {
                "pending_review" => "pending_approval",
                "pending_verification" => "pending_verification",
                _ when emailVerifiedAt is not null => "verified",
                _ when !string.IsNullOrEmpty(email) => "unverified",
                _ => "missing",
            };

        return new LoginUser(
            reader.GetInt32(0),
            reader.GetString(1),
            NullableString(reader, 2),
            NullableString(reader, 3),
            NullableString(reader, 4),
            NullableString(reader, 5),
            NullableString(reader, 6),
            NullableString(reader, 7),
            accountType,
            email,
            NullableString(reader, 10),
            emailVerifiedAt,
            reader.GetBoolean(12),
            NullableDateTime(reader, 13),
            NullableDateTime(reader, 14),
            NullableDateTime(reader, 15),
            recoveryStatus,
            accountType == "display" ? null : NullableString(reader, 17),
            SqliteJson.ReadStringList(reader, 18),
            SqliteJson.ReadStringList(reader, 19),
            SqliteJson.ReadStringList(reader, 20));
    }

    private static string FormatDatabaseDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? NullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? NullableDateTime(SqliteDataReader reader, int ordinal)
    {
        var value = NullableString(reader, ordinal);
        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
            ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified)
            : null;
    }
}
