using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteRecoveryEmailStore(SqliteConnectionFactory connections) : IRecoveryEmailStore
{
    public async Task<int> SubmitAsync(
        int userId,
        string email,
        string normalizedEmail,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        string? currentNormalized;
        DateTime? verifiedAt;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT email_normalized, email_verified_at FROM users WHERE id = $user_id AND is_active = 1 LIMIT 1";
            query.Parameters.AddWithValue("$user_id", userId);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new RecoveryEmailException("User not found or disabled.");
            }
            currentNormalized = NullableString(reader, 0);
            verifiedAt = NullableDateTime(reader, 1);
        }

        if (currentNormalized == normalizedEmail && verifiedAt is not null)
        {
            throw new RecoveryEmailException("That is already the approved recovery email.");
        }
        if (await ExistsAsync(connection, transaction,
            "SELECT 1 FROM users WHERE email_normalized = $email AND id != $user_id LIMIT 1",
            normalizedEmail, userId, cancellationToken))
        {
            throw new RecoveryEmailException("That email address is already associated with another account.");
        }
        if (await ExistsAsync(connection, transaction, """
            SELECT 1 FROM registration_invites
            WHERE email_normalized = $email AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $now
            LIMIT 1
            """, normalizedEmail, now, cancellationToken))
        {
            throw new RecoveryEmailException("That email address already has a pending invitation.");
        }
        if (await ExistsAsync(connection, transaction, """
            SELECT 1 FROM email_change_requests
            WHERE user_id = $user_id AND status IN ('pending_review', 'pending_verification')
            LIMIT 1
            """, userId, cancellationToken))
        {
            throw new RecoveryEmailException("An email change request is already pending.");
        }
        if (await ExistsAsync(connection, transaction, """
            SELECT 1 FROM email_change_requests
            WHERE requested_email_normalized = $email AND status = 'pending_verification'
            LIMIT 1
            """, normalizedEmail, cancellationToken))
        {
            throw new RecoveryEmailException("That email address is awaiting verification for another account.");
        }

        int requestId;
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO email_change_requests
                    (user_id, requested_email, requested_email_normalized, status, requested_at)
                VALUES ($user_id, $email, $normalized, 'pending_review', $now)
                """;
            insert.Parameters.AddWithValue("$user_id", userId);
            insert.Parameters.AddWithValue("$email", email);
            insert.Parameters.AddWithValue("$normalized", normalizedEmail);
            insert.Parameters.AddWithValue("$now", FormatDate(now));
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await using var id = connection.CreateCommand();
            id.Transaction = transaction;
            id.CommandText = "SELECT last_insert_rowid()";
            requestId = Convert.ToInt32(await id.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }
        await AddAuditAsync(connection, transaction, null, userId, "recovery_email_requested", new { request_id = requestId }, now, cancellationToken);
        transaction.Commit();
        return requestId;
    }

    public async Task<IReadOnlyList<RecoveryEmailRequestInfo>> ListPendingAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT request.id, user.id, user.username, user.full_name,
                   COALESCE(NULLIF(user.account_type, ''), 'individual'), user.email,
                   request.requested_email, request.requested_at
            FROM email_change_requests AS request
            JOIN users AS user ON user.id = request.user_id
            WHERE request.status = 'pending_review'
            ORDER BY request.requested_at ASC
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var requests = new List<RecoveryEmailRequestInfo>();
        while (await reader.ReadAsync(cancellationToken))
        {
            requests.Add(new RecoveryEmailRequestInfo(
                reader.GetInt32(0),
                reader.GetInt32(1),
                reader.GetString(2),
                NullableString(reader, 3),
                reader.GetString(4),
                NullableString(reader, 5),
                reader.GetString(6),
                NullableDateTime(reader, 7)));
        }
        return requests;
    }

    public async Task<RecoveryEmailDecisionResult> ReviewAsync(
        int requestId,
        int reviewerId,
        bool approve,
        string reason,
        string? tokenHash,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();

        int userId;
        string username;
        string? currentEmail;
        string requestedEmail;
        string normalizedEmail;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT user.id, user.username, user.email, request.requested_email, request.requested_email_normalized
                FROM email_change_requests AS request
                JOIN users AS user ON user.id = request.user_id
                WHERE request.id = $request_id AND request.status = 'pending_review'
                LIMIT 1
                """;
            query.Parameters.AddWithValue("$request_id", requestId);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new RecoveryEmailException("Pending recovery-email request not found.");
            }
            userId = reader.GetInt32(0);
            username = reader.GetString(1);
            currentEmail = NullableString(reader, 2);
            requestedEmail = reader.GetString(3);
            normalizedEmail = reader.GetString(4);
        }

        if (!await ExistsAsync(connection, transaction, "SELECT 1 FROM users WHERE id = $user_id AND is_active = 1 LIMIT 1", userId, cancellationToken))
        {
            throw new RecoveryEmailException("The account no longer exists or is disabled.");
        }
        if (reviewerId == userId)
        {
            throw new RecoveryEmailException("A user administrator cannot approve their own recovery-email change.");
        }

        var decisionReason = reason.Length > 1000 ? reason[..1000] : reason;
        if (!approve && decisionReason.Length == 0)
        {
            throw new RecoveryEmailException("A reason is required when denying a recovery-email request.");
        }
        decisionReason = decisionReason.Length == 0 ? "Approved by user administrator." : decisionReason;

        if (!approve)
        {
            await using var deny = connection.CreateCommand();
            deny.Transaction = transaction;
            deny.CommandText = """
                UPDATE email_change_requests
                SET reviewed_by_id = $reviewer_id, reviewed_at = $now,
                    decision_reason = $reason, status = 'denied'
                WHERE id = $request_id AND status = 'pending_review'
                """;
            deny.Parameters.AddWithValue("$reviewer_id", reviewerId);
            deny.Parameters.AddWithValue("$now", FormatDate(now));
            deny.Parameters.AddWithValue("$reason", decisionReason);
            deny.Parameters.AddWithValue("$request_id", requestId);
            if (await deny.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new RecoveryEmailException("Pending recovery-email request not found.");
            }
            await AddAuditAsync(connection, transaction, reviewerId, userId, "recovery_email_denied", new { request_id = requestId, reason = decisionReason }, now, cancellationToken);
            transaction.Commit();
            return new RecoveryEmailDecisionResult("denied", username, currentEmail);
        }

        if (await ExistsAsync(connection, transaction,
            "SELECT 1 FROM users WHERE email_normalized = $email AND id != $user_id LIMIT 1",
            normalizedEmail, userId, cancellationToken))
        {
            throw new RecoveryEmailException("That email address is now associated with another account.");
        }
        if (string.IsNullOrEmpty(tokenHash))
        {
            throw new RecoveryEmailException("Unable to create email-verification capability.");
        }

        await using (var approval = connection.CreateCommand())
        {
            approval.Transaction = transaction;
            approval.CommandText = """
                UPDATE email_change_requests
                SET reviewed_by_id = $reviewer_id, reviewed_at = $now,
                    decision_reason = $reason, status = 'pending_verification',
                    verification_token_hash = $token_hash, verification_expires_at = $expires_at
                WHERE id = $request_id AND status = 'pending_review'
                """;
            approval.Parameters.AddWithValue("$reviewer_id", reviewerId);
            approval.Parameters.AddWithValue("$now", FormatDate(now));
            approval.Parameters.AddWithValue("$reason", decisionReason);
            approval.Parameters.AddWithValue("$token_hash", tokenHash);
            approval.Parameters.AddWithValue("$expires_at", FormatDate(now.AddHours(24)));
            approval.Parameters.AddWithValue("$request_id", requestId);
            if (await approval.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new RecoveryEmailException("Pending recovery-email request not found.");
            }
        }
        await AddAuditAsync(connection, transaction, reviewerId, userId, "recovery_email_approved_pending_verification", new { request_id = requestId }, now, cancellationToken);
        transaction.Commit();
        return new RecoveryEmailDecisionResult("pending_verification", username, requestedEmail);
    }

    public async Task<bool> VerifyAsync(string tokenHash, DateTime now, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        int requestId;
        int userId;
        string email;
        string normalizedEmail;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT request.id, request.user_id, request.requested_email, request.requested_email_normalized
                FROM email_change_requests AS request
                WHERE request.verification_token_hash = $token_hash
                  AND request.status = 'pending_verification'
                  AND request.verification_expires_at > $now
                LIMIT 1
                """;
            query.Parameters.AddWithValue("$token_hash", tokenHash);
            query.Parameters.AddWithValue("$now", FormatDate(now));
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return false;
            }
            requestId = reader.GetInt32(0);
            userId = reader.GetInt32(1);
            email = reader.GetString(2);
            normalizedEmail = reader.GetString(3);
        }

        if (!await ExistsAsync(connection, transaction, "SELECT 1 FROM users WHERE id = $user_id AND is_active = 1 LIMIT 1", userId, cancellationToken))
        {
            return false;
        }
        if (await ExistsAsync(connection, transaction,
            "SELECT 1 FROM users WHERE email_normalized = $email AND id != $user_id LIMIT 1",
            normalizedEmail, userId, cancellationToken))
        {
            await using var conflict = connection.CreateCommand();
            conflict.Transaction = transaction;
            conflict.CommandText = "UPDATE email_change_requests SET status = 'conflict' WHERE id = $request_id";
            conflict.Parameters.AddWithValue("$request_id", requestId);
            await conflict.ExecuteNonQueryAsync(cancellationToken);
            transaction.Commit();
            return false;
        }

        await using (var updateUser = connection.CreateCommand())
        {
            updateUser.Transaction = transaction;
            updateUser.CommandText = """
                UPDATE users SET email = $email, email_normalized = $normalized, email_verified_at = $now
                WHERE id = $user_id AND is_active = 1
                """;
            updateUser.Parameters.AddWithValue("$email", email);
            updateUser.Parameters.AddWithValue("$normalized", normalizedEmail);
            updateUser.Parameters.AddWithValue("$now", FormatDate(now));
            updateUser.Parameters.AddWithValue("$user_id", userId);
            if (await updateUser.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return false;
            }
        }
        await using (var completeRequest = connection.CreateCommand())
        {
            completeRequest.Transaction = transaction;
            completeRequest.CommandText = """
                UPDATE email_change_requests
                SET status = 'completed', verified_at = $now, verification_token_hash = NULL
                WHERE id = $request_id
                """;
            completeRequest.Parameters.AddWithValue("$now", FormatDate(now));
            completeRequest.Parameters.AddWithValue("$request_id", requestId);
            await completeRequest.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddAuditAsync(connection, transaction, null, userId, "recovery_email_verified", new { request_id = requestId }, now, cancellationToken);
        transaction.Commit();
        return true;
    }

    public async Task<RecoveryEmailVerification> ResendAsync(
        int userId,
        string tokenHash,
        DateTime now,
        DateTime expiresAt,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        int requestId;
        string email;
        string username;
        DateTime? reviewedAt;
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = """
                SELECT request.id, request.requested_email, request.reviewed_at, user.username
                FROM email_change_requests AS request
                JOIN users AS user ON user.id = request.user_id
                WHERE request.user_id = $user_id AND request.status = 'pending_verification'
                ORDER BY request.requested_at DESC
                LIMIT 1
                """;
            query.Parameters.AddWithValue("$user_id", userId);
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                throw new RecoveryEmailException("There is no approved recovery-email verification waiting to be sent.");
            }
            requestId = reader.GetInt32(0);
            email = reader.GetString(1);
            reviewedAt = NullableDateTime(reader, 2);
            username = reader.GetString(3);
        }
        if (reviewedAt is not null && reviewedAt > now.AddMinutes(-5))
        {
            throw new RecoveryEmailException("Wait five minutes before requesting another verification email.");
        }
        if (!await ExistsAsync(connection, transaction, "SELECT 1 FROM users WHERE id = $user_id AND is_active = 1 LIMIT 1", userId, cancellationToken))
        {
            throw new RecoveryEmailException("User not found or disabled.");
        }

        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE email_change_requests
            SET verification_token_hash = $token_hash, verification_expires_at = $expires_at, reviewed_at = $now
            WHERE id = $request_id AND status = 'pending_verification'
            """;
        update.Parameters.AddWithValue("$token_hash", tokenHash);
        update.Parameters.AddWithValue("$expires_at", FormatDate(expiresAt));
        update.Parameters.AddWithValue("$now", FormatDate(now));
        update.Parameters.AddWithValue("$request_id", requestId);
        if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
        {
            throw new RecoveryEmailException("There is no approved recovery-email verification waiting to be sent.");
        }
        transaction.Commit();
        return new RecoveryEmailVerification(username, email);
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        int userId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$user_id", userId);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        string email,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$email", email);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        string email,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$now", FormatDate(now));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<bool> ExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        string email,
        int userId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$user_id", userId);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task AddAuditAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int? actorId,
        int? subjectId,
        string eventType,
        object detail,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO account_audit_events
                (actor_user_id, subject_user_id, event_type, event_detail, created_at)
            VALUES ($actor_id, $subject_id, $event_type, $detail, $created_at)
            """;
        command.Parameters.AddWithValue("$actor_id", (object?)actorId ?? DBNull.Value);
        command.Parameters.AddWithValue("$subject_id", (object?)subjectId ?? DBNull.Value);
        command.Parameters.AddWithValue("$event_type", eventType);
        command.Parameters.AddWithValue("$detail", JsonSerializer.Serialize(detail));
        command.Parameters.AddWithValue("$created_at", FormatDate(now));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string? NullableString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? NullableDateTime(SqliteDataReader reader, int ordinal)
    {
        var value = NullableString(reader, ordinal);
        return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
            ? DateTime.SpecifyKind(parsed, DateTimeKind.Unspecified)
            : null;
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
