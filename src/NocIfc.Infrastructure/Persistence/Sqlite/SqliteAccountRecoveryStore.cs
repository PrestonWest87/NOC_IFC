using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAccountRecoveryStore(SqliteConnectionFactory connections) : IAccountRecoveryStore
{
    public async Task<PasswordResetSubmission> SubmitPasswordResetRequestAsync(
        string normalizedIdentifier,
        string identifierHash,
        string? requesterIp,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var hourCutoff = FormatDate(now.AddHours(-1));

        if (requesterIp is not null
            && await CountAsync(
                connection,
                transaction,
                "SELECT COUNT(*) FROM password_reset_requests WHERE requester_ip = $value AND requested_at >= $cutoff",
                requesterIp,
                hourCutoff,
                cancellationToken) >= 10)
        {
            transaction.Commit();
            return new PasswordResetSubmission(true, null, null);
        }
        if (await CountAsync(
                connection,
                transaction,
                "SELECT COUNT(*) FROM password_reset_requests WHERE identifier_hash = $value AND requested_at >= $cutoff",
                identifierHash,
                hourCutoff,
                cancellationToken) >= 5)
        {
            transaction.Commit();
            return new PasswordResetSubmission(true, null, null);
        }

        int? userId = null;
        string? accountType = null;
        if (normalizedIdentifier.Length > 0)
        {
            await using var userQuery = connection.CreateCommand();
            userQuery.Transaction = transaction;
            userQuery.CommandText = """
                SELECT id, account_type, is_active FROM users
                WHERE lower(username) = $identifier OR email_normalized = $identifier
                LIMIT 1
                """;
            userQuery.Parameters.AddWithValue("$identifier", normalizedIdentifier);
            await using var userReader = await userQuery.ExecuteReaderAsync(cancellationToken);
            if (await userReader.ReadAsync(cancellationToken) && userReader.GetBoolean(2))
            {
                userId = userReader.GetInt32(0);
                accountType = userReader.IsDBNull(1) ? "individual" : userReader.GetString(1);
            }
        }

        if (userId is null)
        {
            await using var unmatched = connection.CreateCommand();
            unmatched.Transaction = transaction;
            unmatched.CommandText = """
                INSERT INTO password_reset_requests
                    (user_id, identifier_hash, requester_ip, status, requested_at)
                VALUES (NULL, $identifier_hash, $requester_ip, 'unmatched', $now)
                """;
            AddRequestParameters(unmatched, identifierHash, requesterIp, now);
            await unmatched.ExecuteNonQueryAsync(cancellationToken);
            transaction.Commit();
            return new PasswordResetSubmission(false, null, null);
        }

        var pendingSince = FormatDate(now.AddMinutes(-30));
        int? requestId;
        await using (var pending = connection.CreateCommand())
        {
            pending.Transaction = transaction;
            pending.CommandText = """
                SELECT id FROM password_reset_requests
                WHERE user_id = $user_id AND status = 'pending_review' AND requested_at >= $since
                LIMIT 1
                """;
            pending.Parameters.AddWithValue("$user_id", userId.Value);
            pending.Parameters.AddWithValue("$since", pendingSince);
            var existingId = await pending.ExecuteScalarAsync(cancellationToken);
            requestId = existingId is null ? null : Convert.ToInt32(existingId, CultureInfo.InvariantCulture);
        }

        if (requestId is null)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO password_reset_requests
                    (user_id, identifier_hash, requester_ip, status, requested_at)
                VALUES ($user_id, $identifier_hash, $requester_ip, 'pending_review', $now)
                """;
            insert.Parameters.AddWithValue("$user_id", userId.Value);
            AddRequestParameters(insert, identifierHash, requesterIp, now);
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await using var id = connection.CreateCommand();
            id.Transaction = transaction;
            id.CommandText = "SELECT last_insert_rowid()";
            requestId = Convert.ToInt32(await id.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
            await AddAuditAsync(
                connection,
                transaction,
                null,
                userId,
                "password_reset_requested",
                new { request_id = requestId, account_type = accountType },
                now,
                cancellationToken);
        }

        transaction.Commit();
        return new PasswordResetSubmission(false, requestId, userId);
    }

    public async Task<IReadOnlyList<PasswordResetRequestInfo>> ListPasswordResetRequestsAsync(
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT request.id, user.id, user.username, user.full_name, user.email,
                   user.email_verified_at, COALESCE(NULLIF(user.account_type, ''), 'individual'),
                   request.requested_at
            FROM password_reset_requests AS request
            JOIN users AS user ON user.id = request.user_id
            WHERE request.status = 'pending_review'
            ORDER BY request.requested_at ASC
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var requests = new List<PasswordResetRequestInfo>();
        while (await reader.ReadAsync(cancellationToken))
        {
            requests.Add(new PasswordResetRequestInfo(
                reader.GetInt32(0),
                reader.GetInt32(1),
                reader.GetString(2),
                NullableString(reader, 3),
                NullableString(reader, 4),
                !reader.IsDBNull(5),
                reader.GetString(6),
                NullableDateTime(reader, 7)));
        }
        return requests;
    }

    public async Task<PasswordResetDecisionResult> ReviewPasswordResetRequestAsync(
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
        string? email;
        bool isActive;
        bool emailVerified;
        string accountType;
        await using (var request = connection.CreateCommand())
        {
            request.Transaction = transaction;
            request.CommandText = """
                SELECT user.id, user.username, user.email, user.is_active,
                       user.email_verified_at, COALESCE(NULLIF(user.account_type, ''), 'individual')
                FROM password_reset_requests AS reset_request
                LEFT JOIN users AS user ON user.id = reset_request.user_id
                WHERE reset_request.id = $request_id AND reset_request.status = 'pending_review'
                LIMIT 1
                """;
            request.Parameters.AddWithValue("$request_id", requestId);
            await using var reader = await request.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken) || reader.IsDBNull(0))
            {
                throw new AccountRecoveryException("Pending password-reset request not found.");
            }
            userId = reader.GetInt32(0);
            username = reader.GetString(1);
            email = NullableString(reader, 2);
            isActive = reader.GetBoolean(3);
            emailVerified = !reader.IsDBNull(4);
            accountType = reader.GetString(5);
        }

        if (!isActive)
        {
            throw new AccountRecoveryException("The account no longer exists or is disabled.");
        }
        if (userId == reviewerId)
        {
            throw new AccountRecoveryException("A user administrator cannot approve their own password-reset request.");
        }

        var decisionReason = reason.Length > 1000 ? reason[..1000] : reason;
        if (!approve && decisionReason.Length == 0)
        {
            throw new AccountRecoveryException("A reason is required when denying a password-reset request.");
        }
        decisionReason = decisionReason.Length == 0 ? "Approved by user administrator." : decisionReason;

        if (!approve)
        {
            await using var denial = connection.CreateCommand();
            denial.Transaction = transaction;
            denial.CommandText = """
                UPDATE password_reset_requests
                SET reviewed_by_id = $reviewer_id, reviewed_at = $now,
                    decision_reason = $reason, status = 'denied'
                WHERE id = $request_id AND status = 'pending_review'
                """;
            denial.Parameters.AddWithValue("$reviewer_id", reviewerId);
            denial.Parameters.AddWithValue("$now", FormatDate(now));
            denial.Parameters.AddWithValue("$reason", decisionReason);
            denial.Parameters.AddWithValue("$request_id", requestId);
            if (await denial.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new AccountRecoveryException("Pending password-reset request not found.");
            }
            await AddAuditAsync(connection, transaction, reviewerId, userId, "password_reset_denied", new { request_id = requestId, reason = decisionReason }, now, cancellationToken);
            transaction.Commit();
            return new PasswordResetDecisionResult("denied", username, emailVerified ? email : null);
        }

        if (string.IsNullOrEmpty(email) || !emailVerified || accountType == "display")
        {
            throw new AccountRecoveryException("This account has no approved recovery email. Use administrator-assisted recovery.");
        }
        if (string.IsNullOrEmpty(tokenHash))
        {
            throw new AccountRecoveryException("Unable to create password-reset capability.");
        }

        await using (var insertToken = connection.CreateCommand())
        {
            insertToken.Transaction = transaction;
            insertToken.CommandText = """
                INSERT INTO password_reset_tokens (request_id, user_id, token_hash, created_at, expires_at)
                VALUES ($request_id, $user_id, $token_hash, $now, $expires_at)
                """;
            insertToken.Parameters.AddWithValue("$request_id", requestId);
            insertToken.Parameters.AddWithValue("$user_id", userId);
            insertToken.Parameters.AddWithValue("$token_hash", tokenHash);
            insertToken.Parameters.AddWithValue("$now", FormatDate(now));
            insertToken.Parameters.AddWithValue("$expires_at", FormatDate(now.AddMinutes(60)));
            await insertToken.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var approval = connection.CreateCommand())
        {
            approval.Transaction = transaction;
            approval.CommandText = """
                UPDATE password_reset_requests
                SET reviewed_by_id = $reviewer_id, reviewed_at = $now,
                    decision_reason = $reason, status = 'approved', reset_email_sent_at = $now
                WHERE id = $request_id AND status = 'pending_review'
                """;
            approval.Parameters.AddWithValue("$reviewer_id", reviewerId);
            approval.Parameters.AddWithValue("$now", FormatDate(now));
            approval.Parameters.AddWithValue("$reason", decisionReason);
            approval.Parameters.AddWithValue("$request_id", requestId);
            if (await approval.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                throw new AccountRecoveryException("Pending password-reset request not found.");
            }
        }
        await AddAuditAsync(connection, transaction, reviewerId, userId, "password_reset_approved", new { request_id = requestId }, now, cancellationToken);
        transaction.Commit();
        return new PasswordResetDecisionResult("approved", username, email);
    }

    public async Task<bool> HasValidPasswordResetTokenAsync(
        string tokenHash,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM password_reset_tokens AS token
            JOIN users AS user ON user.id = token.user_id
            WHERE token.token_hash = $token_hash AND token.used_at IS NULL
              AND token.expires_at > $now AND user.is_active = 1
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$token_hash", tokenHash);
        command.Parameters.AddWithValue("$now", FormatDate(now));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    public async Task<bool> CompletePasswordResetAsync(
        string tokenHash,
        string passwordHash,
        DateTime now,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        int requestId;
        int userId;
        await using (var lookup = connection.CreateCommand())
        {
            lookup.Transaction = transaction;
            lookup.CommandText = """
                SELECT token.request_id, token.user_id
                FROM password_reset_tokens AS token
                JOIN users AS user ON user.id = token.user_id
                WHERE token.token_hash = $token_hash AND token.used_at IS NULL
                  AND token.expires_at > $now AND user.is_active = 1
                LIMIT 1
                """;
            lookup.Parameters.AddWithValue("$token_hash", tokenHash);
            lookup.Parameters.AddWithValue("$now", FormatDate(now));
            await using var reader = await lookup.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return false;
            }
            requestId = reader.GetInt32(0);
            userId = reader.GetInt32(1);
        }

        await using (var update = connection.CreateCommand())
        {
            update.Transaction = transaction;
            update.CommandText = "UPDATE users SET password_hash = $password_hash, session_token = NULL WHERE id = $user_id AND is_active = 1";
            update.Parameters.AddWithValue("$password_hash", passwordHash);
            update.Parameters.AddWithValue("$user_id", userId);
            if (await update.ExecuteNonQueryAsync(cancellationToken) != 1)
            {
                return false;
            }
        }
        await using (var deleteSessions = connection.CreateCommand())
        {
            deleteSessions.Transaction = transaction;
            deleteSessions.CommandText = "DELETE FROM user_sessions WHERE user_id = $user_id";
            deleteSessions.Parameters.AddWithValue("$user_id", userId);
            await deleteSessions.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var consumeTokens = connection.CreateCommand())
        {
            consumeTokens.Transaction = transaction;
            consumeTokens.CommandText = "UPDATE password_reset_tokens SET used_at = $now WHERE user_id = $user_id AND used_at IS NULL";
            consumeTokens.Parameters.AddWithValue("$now", FormatDate(now));
            consumeTokens.Parameters.AddWithValue("$user_id", userId);
            await consumeTokens.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var completeRequest = connection.CreateCommand())
        {
            completeRequest.Transaction = transaction;
            completeRequest.CommandText = "UPDATE password_reset_requests SET status = 'completed' WHERE id = $request_id";
            completeRequest.Parameters.AddWithValue("$request_id", requestId);
            await completeRequest.ExecuteNonQueryAsync(cancellationToken);
        }
        await AddAuditAsync(connection, transaction, null, userId, "password_reset_completed", new { }, now, cancellationToken);
        transaction.Commit();
        return true;
    }

    private static async Task<long> CountAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        string value,
        string cutoff,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$value", value);
        command.Parameters.AddWithValue("$cutoff", cutoff);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static void AddRequestParameters(SqliteCommand command, string identifierHash, string? requesterIp, DateTime now)
    {
        command.Parameters.AddWithValue("$identifier_hash", identifierHash);
        command.Parameters.AddWithValue("$requester_ip", (object?)requesterIp ?? DBNull.Value);
        command.Parameters.AddWithValue("$now", FormatDate(now));
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
