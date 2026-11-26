using System.Security.Cryptography;
using System.Text;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAccountRecoveryStoreTests
{
    [Fact]
    public async Task ResetReviewIsRateLimitedSingleUseAuditedAndRevokesSessions()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-reset-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, email TEXT, email_normalized TEXT, email_verified_at TEXT,
                        account_type TEXT, is_active INTEGER, password_hash TEXT, session_token TEXT
                    );
                    CREATE TABLE user_sessions (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT);
                    CREATE TABLE password_reset_requests (
                        id INTEGER PRIMARY KEY, user_id INTEGER, identifier_hash TEXT, requester_ip TEXT,
                        status TEXT, requested_at TEXT, reviewed_by_id INTEGER, reviewed_at TEXT,
                        decision_reason TEXT, reset_email_sent_at TEXT
                    );
                    CREATE TABLE password_reset_tokens (
                        id INTEGER PRIMARY KEY, request_id INTEGER, user_id INTEGER,
                        token_hash TEXT, created_at TEXT, expires_at TEXT, used_at TEXT
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at TEXT
                    );
                    INSERT INTO users VALUES
                        (1, 'alice', 'Alice', 'alice@example.com', 'alice@example.com', '2026-01-01 00:00:00.000000', 'individual', 1, 'old-hash', 'legacy-token'),
                        (2, 'admin', 'Admin', 'admin@example.com', 'admin@example.com', '2026-01-01 00:00:00.000000', 'individual', 1, 'admin-hash', NULL);
                    INSERT INTO user_sessions VALUES (1, 1, 'modern-token');
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteAccountRecoveryStore(connections);
            var now = DateTime.UtcNow;
            var identifierHash = CapabilityTokenHash.Sha256("alice");
            var first = await store.SubmitPasswordResetRequestAsync(
                "alice", identifierHash, "192.0.2.5", now, CancellationToken.None);
            var reused = await store.SubmitPasswordResetRequestAsync(
                "alice", identifierHash, "192.0.2.5", now.AddMinutes(1), CancellationToken.None);
            var requestId = first.RequestId ?? throw new InvalidOperationException("Expected a pending reset request.");
            Assert.Equal(first.RequestId, reused.RequestId);
            Assert.Single(await store.ListPasswordResetRequestsAsync(CancellationToken.None));

            for (var index = 0; index < 5; index++)
            {
                await store.SubmitPasswordResetRequestAsync(
                    "unknown", CapabilityTokenHash.Sha256("unknown"), null, now.AddMinutes(index), CancellationToken.None);
            }
            var limited = await store.SubmitPasswordResetRequestAsync(
                "unknown", CapabilityTokenHash.Sha256("unknown"), null, now.AddMinutes(6), CancellationToken.None);
            Assert.True(limited.RateLimited);
            Assert.Null(limited.RequestId);

            await Assert.ThrowsAsync<AccountRecoveryException>(() => store.ReviewPasswordResetRequestAsync(
                requestId, 1, true, "Self review", "unused", now, CancellationToken.None));

            const string rawToken = "single-use-reset-token";
            var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))).ToLowerInvariant();
            var approved = await store.ReviewPasswordResetRequestAsync(
                requestId, 2, true, "Verified identity", tokenHash, now, CancellationToken.None);
            Assert.Equal("approved", approved.Status);
            Assert.Equal("alice@example.com", approved.Email);
            Assert.True(await store.HasValidPasswordResetTokenAsync(tokenHash, now, CancellationToken.None));
            Assert.True(await store.CompletePasswordResetAsync(tokenHash, "new-bcrypt-hash", now, CancellationToken.None));
            Assert.False(await store.CompletePasswordResetAsync(tokenHash, "replay-hash", now, CancellationToken.None));

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = """
                SELECT user.password_hash, user.session_token,
                       (SELECT COUNT(*) FROM user_sessions WHERE user_id = user.id),
                       request.status, token.used_at,
                       (SELECT COUNT(*) FROM password_reset_requests WHERE identifier_hash = $unknown_hash)
                FROM users AS user
                JOIN password_reset_requests AS request ON request.id = $request_id
                JOIN password_reset_tokens AS token ON token.request_id = request.id
                WHERE user.id = 1
                """;
            command.Parameters.AddWithValue("$unknown_hash", CapabilityTokenHash.Sha256("unknown"));
            command.Parameters.AddWithValue("$request_id", requestId);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("new-bcrypt-hash", reader.GetString(0));
            Assert.True(reader.IsDBNull(1));
            Assert.Equal(0, reader.GetInt32(2));
            Assert.Equal("completed", reader.GetString(3));
            Assert.False(reader.IsDBNull(4));
            Assert.Equal(5, reader.GetInt32(5));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
