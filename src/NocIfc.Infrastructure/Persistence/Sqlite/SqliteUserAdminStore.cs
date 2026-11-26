using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteUserAdminStore(SqliteConnectionFactory connections) : IUserAdminStore
{
    public async Task<RegistrationInviteCreateResult> CreateRegistrationInviteAsync(
        string username,
        string email,
        string normalizedEmail,
        string role,
        string tokenHash,
        string createdBy,
        int ttlHours,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        if (await ExistsAsync(connection, transaction, "SELECT 1 FROM users WHERE username = $value LIMIT 1", "$value", username, cancellationToken))
        {
            transaction.Commit();
            return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.UsernameExists);
        }
        if (await ExistsAsync(connection, transaction, "SELECT 1 FROM users WHERE email_normalized = $value LIMIT 1", "$value", normalizedEmail, cancellationToken))
        {
            transaction.Commit();
            return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.EmailInUse);
        }
        if (await ExistsAsync(connection, transaction, """
            SELECT 1 FROM email_change_requests
            WHERE requested_email_normalized = $value
              AND status IN ('pending_review', 'pending_verification')
            LIMIT 1
            """, "$value", normalizedEmail, cancellationToken))
        {
            transaction.Commit();
            return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.EmailPendingRecovery);
        }
        if (!await ExistsAsync(connection, transaction, "SELECT 1 FROM roles WHERE name = $value LIMIT 1", "$value", role, cancellationToken))
        {
            transaction.Commit();
            return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.RoleNotFound);
        }
        if (await InviteExistsAsync(connection, transaction, username, normalizedEmail, now, cancellationToken))
        {
            transaction.Commit();
            return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.EmailHasPendingInvite);
        }

        await using (var replace = connection.CreateCommand())
        {
            replace.Transaction = transaction;
            replace.CommandText = """
                UPDATE registration_invites SET used_at = $now
                WHERE username = $username AND used_at IS NULL AND revoked_at IS NULL
                """;
            replace.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            replace.Parameters.AddWithValue("$username", username);
            await replace.ExecuteNonQueryAsync(cancellationToken);
        }

        var expiresAt = now.AddHours(Math.Clamp(ttlHours, 1, 336));
        int inviteId;
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO registration_invites (
                    username, role, token_hash, created_by, created_at, expires_at,
                    email, email_normalized, account_type
                ) VALUES (
                    $username, $role, $token_hash, $created_by, $created_at, $expires_at,
                    $email, $email_normalized, 'individual'
                )
                """;
            insert.Parameters.AddWithValue("$username", username);
            insert.Parameters.AddWithValue("$role", role);
            insert.Parameters.AddWithValue("$token_hash", tokenHash);
            insert.Parameters.AddWithValue("$created_by", createdBy);
            insert.Parameters.AddWithValue("$created_at", FormatDatabaseDate(now));
            insert.Parameters.AddWithValue("$expires_at", FormatDatabaseDate(expiresAt));
            insert.Parameters.AddWithValue("$email", email);
            insert.Parameters.AddWithValue("$email_normalized", normalizedEmail);
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await using var id = connection.CreateCommand();
            id.Transaction = transaction;
            id.CommandText = "SELECT last_insert_rowid()";
            inviteId = Convert.ToInt32(await id.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        transaction.Commit();
        return new RegistrationInviteCreateResult(RegistrationInviteCreateStatus.Created, inviteId, expiresAt);
    }

    public async Task<IReadOnlyList<PendingRegistrationInvite>> GetPendingInvitationsAsync(
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, username, email, role, created_at, expires_at, created_by, revoked_at
            FROM registration_invites
            WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > $now
            ORDER BY created_at DESC
            """;
        command.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var invitations = new List<PendingRegistrationInvite>();
        while (await reader.ReadAsync(cancellationToken))
        {
            invitations.Add(new PendingRegistrationInvite(
                reader.GetInt32(0),
                reader.GetString(1),
                reader.GetString(2),
                reader.GetString(3),
                NullableDateTime(reader, 4),
                DateTime.SpecifyKind(DateTime.Parse(reader.GetString(5), CultureInfo.InvariantCulture), DateTimeKind.Unspecified),
                reader.GetString(6),
                NullableDateTime(reader, 7)));
        }
        return invitations;
    }

    public async Task<bool> RevokeInvitationAsync(
        int inviteId,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        string username;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT username FROM registration_invites WHERE id = $id AND used_at IS NULL AND revoked_at IS NULL";
            query.Parameters.AddWithValue("$id", inviteId);
            var value = await query.ExecuteScalarAsync(cancellationToken);
            if (value is null)
            {
                return false;
            }
            username = Convert.ToString(value, CultureInfo.InvariantCulture)!;
        }
        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE registration_invites SET revoked_at = $now WHERE id = $id AND used_at IS NULL AND revoked_at IS NULL";
            update.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            update.Parameters.AddWithValue("$id", inviteId);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return false;
            }
        }
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            null,
            "registration_invite_revoked",
            new { invite_id = inviteId, username },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<string?> GetPublicAppUrlAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT public_app_url FROM system_config ORDER BY id LIMIT 1";
        var value = await command.ExecuteScalarAsync(cancellationToken);
        return value is null or DBNull ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public async Task<DisplayAccountCreateResult> CreateDisplayAccountAsync(
        string username,
        string passwordHash,
        string role,
        string fullName,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        await using (var duplicate = connection.CreateCommand())
        {
            duplicate.Transaction = transaction;
            duplicate.CommandText = "SELECT 1 FROM users WHERE lower(username) = lower($username) LIMIT 1";
            duplicate.Parameters.AddWithValue("$username", username);
            if (await duplicate.ExecuteScalarAsync(cancellationToken) is not null)
            {
                transaction.Commit();
                return new DisplayAccountCreateResult(DisplayAccountCreateStatus.UsernameTaken);
            }
        }

        await using (var roleLookup = connection.CreateCommand())
        {
            roleLookup.Transaction = transaction;
            roleLookup.CommandText = "SELECT 1 FROM roles WHERE lower(name) = lower($role) LIMIT 1";
            roleLookup.Parameters.AddWithValue("$role", role);
            if (await roleLookup.ExecuteScalarAsync(cancellationToken) is null)
            {
                transaction.Commit();
                return new DisplayAccountCreateResult(DisplayAccountCreateStatus.RoleNotFound);
            }
        }

        int userId;
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO users (
                    username, password_hash, role, full_name, default_shift, theme,
                    account_type, is_active, created_at
                ) VALUES (
                    $username, $password_hash, $role, $full_name, 'No Shift', 'standard',
                    'display', 1, $created_at
                )
                """;
            insert.Parameters.AddWithValue("$username", username);
            insert.Parameters.AddWithValue("$password_hash", passwordHash);
            insert.Parameters.AddWithValue("$role", role);
            insert.Parameters.AddWithValue("$full_name", fullName);
            insert.Parameters.AddWithValue("$created_at", FormatDatabaseDate(now));
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await using var idCommand = connection.CreateCommand();
            idCommand.Transaction = transaction;
            idCommand.CommandText = "SELECT last_insert_rowid()";
            userId = Convert.ToInt32(await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            userId,
            "display_account_created",
            new { role },
            cancellationToken);
        transaction.Commit();
        return new DisplayAccountCreateResult(DisplayAccountCreateStatus.Created, userId);
    }

    public async Task<UserAdminTarget?> FindTargetAsync(string username, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, username, role, COALESCE(NULLIF(account_type, ''), 'individual'),
                   email, email_verified_at
            FROM users WHERE username = $username LIMIT 1
            """;
        command.Parameters.AddWithValue("$username", username);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new UserAdminTarget(
            reader.GetInt32(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetString(2),
            reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            !reader.IsDBNull(5));
    }

    public async Task<bool> ChangeRoleAsync(
        UserAdminTarget target,
        string role,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE users SET role = $new_role, session_token = NULL
            WHERE id = $user_id AND role IS $old_role
            """;
        update.Parameters.AddWithValue("$new_role", role);
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        await DeleteSessionsAsync(connection, transaction, target.Id, cancellationToken);
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            target.Id,
            "user_role_changed",
            new { from = target.Role, to = role },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<bool> SetActiveAsync(
        UserAdminTarget target,
        bool isActive,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE users SET is_active = $is_active,
                session_token = CASE WHEN $is_active = 1 THEN session_token ELSE NULL END
            WHERE id = $user_id AND role IS $old_role
            """;
        update.Parameters.AddWithValue("$is_active", isActive ? 1 : 0);
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        if (!isActive)
        {
            await DeleteSessionsAsync(connection, transaction, target.Id, cancellationToken);
        }
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            target.Id,
            isActive ? "user_activated" : "user_disabled",
            new { },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<bool> RevokeSessionsAsync(
        UserAdminTarget target,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE users SET session_token = NULL WHERE id = $user_id AND role IS $old_role";
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        await DeleteSessionsAsync(connection, transaction, target.Id, cancellationToken);
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            target.Id,
            "user_sessions_revoked",
            new { },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<bool> AdministratorResetAsync(
        UserAdminTarget target,
        string passwordHash,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = "UPDATE users SET password_hash = $password_hash, session_token = NULL WHERE id = $user_id AND role IS $old_role";
        update.Parameters.AddWithValue("$password_hash", passwordHash);
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        await DeleteSessionsAsync(connection, transaction, target.Id, cancellationToken);
        await using (var tokens = connection.CreateCommand())
        {
            tokens.Transaction = transaction;
            tokens.CommandText = "UPDATE password_reset_tokens SET used_at = $now WHERE user_id = $user_id AND used_at IS NULL";
            tokens.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
            tokens.Parameters.AddWithValue("$user_id", target.Id);
            await tokens.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            target.Id,
            "administrator_password_reset",
            new { },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<bool> UpdateIdentityAsync(
        UserAdminTarget target,
        string fullName,
        string jobTitle,
        string contactInfo,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE users
            SET full_name = $full_name, job_title = $job_title, contact_info = $contact_info
            WHERE id = $user_id AND role IS $old_role
            """;
        update.Parameters.AddWithValue("$full_name", fullName);
        update.Parameters.AddWithValue("$job_title", jobTitle);
        update.Parameters.AddWithValue("$contact_info", contactInfo);
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        await AddAuditAsync(connection, transaction, actorUserId, target.Id, "user_profile_updated", new { }, cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<bool> SetAccountTypeAsync(
        UserAdminTarget target,
        string accountType,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE users
            SET account_type = $account_type,
                session_token = CASE WHEN COALESCE(NULLIF(account_type, ''), 'individual') != $account_type THEN NULL ELSE session_token END
            WHERE id = $user_id AND role IS $old_role
            """;
        update.Parameters.AddWithValue("$account_type", accountType);
        AddTargetParameters(update, target);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            return false;
        }

        if (!string.Equals(target.AccountType, accountType, StringComparison.Ordinal))
        {
            await DeleteSessionsAsync(connection, transaction, target.Id, cancellationToken);
        }
        await AddAuditAsync(
            connection,
            transaction,
            actorUserId,
            target.Id,
            "account_type_changed",
            new { from = string.IsNullOrEmpty(target.AccountType) ? "individual" : target.AccountType, to = accountType },
            cancellationToken);
        transaction.Commit();
        return true;
    }

    private static void AddTargetParameters(SqliteCommand command, UserAdminTarget target)
    {
        command.Parameters.AddWithValue("$user_id", target.Id);
        command.Parameters.AddWithValue("$old_role", (object?)target.Role ?? DBNull.Value);
    }

    private static string FormatDatabaseDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static DateTime? NullableDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.TryParse(reader.GetString(ordinal), CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
            ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified)
            : null;
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        string parameter,
        string value,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue(parameter, value);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<bool> InviteExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string username,
        string normalizedEmail,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT 1 FROM registration_invites
            WHERE email_normalized = $email AND username <> $username
              AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $now
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$email", normalizedEmail);
        command.Parameters.AddWithValue("$username", username);
        command.Parameters.AddWithValue("$now", FormatDatabaseDate(now));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task DeleteSessionsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int userId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "DELETE FROM user_sessions WHERE user_id = $user_id";
        command.Parameters.AddWithValue("$user_id", userId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task AddAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int actorUserId,
        int? subjectUserId,
        string eventType,
        object detail,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO account_audit_events
                (actor_user_id, subject_user_id, event_type, event_detail, created_at)
            VALUES ($actor_id, $subject_id, $event_type, $event_detail, $created_at)
            """;
        command.Parameters.AddWithValue("$actor_id", actorUserId);
        command.Parameters.AddWithValue("$subject_id", (object?)subjectUserId ?? DBNull.Value);
        command.Parameters.AddWithValue("$event_type", eventType);
        command.Parameters.AddWithValue("$event_detail", JsonSerializer.Serialize(detail));
        command.Parameters.AddWithValue(
            "$created_at",
            DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
