using NocIfc.Application.Features.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRecoveryEmailStoreTests
{
    [Fact]
    public async Task RecoveryEmailRequiresReviewVerificationAndResendCooldown()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-email-recovery-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, email TEXT, email_normalized TEXT,
                        email_verified_at TEXT, account_type TEXT, is_active INTEGER
                    );
                    CREATE TABLE registration_invites (
                        id INTEGER PRIMARY KEY, email_normalized TEXT, used_at TEXT, revoked_at TEXT, expires_at TEXT
                    );
                    CREATE TABLE email_change_requests (
                        id INTEGER PRIMARY KEY, user_id INTEGER, requested_email TEXT, requested_email_normalized TEXT,
                        status TEXT, requested_at TEXT, reviewed_by_id INTEGER, reviewed_at TEXT,
                        decision_reason TEXT, verification_token_hash TEXT, verification_expires_at TEXT, verified_at TEXT
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at TEXT
                    );
                    INSERT INTO users VALUES
                        (1, 'admin', 'Admin', 'admin@example.com', 'admin@example.com', '2026-01-01 00:00:00.000000', 'individual', 1),
                        (2, 'alice', 'Alice', NULL, NULL, NULL, 'individual', 1),
                        (3, 'bob', 'Bob', 'taken@example.com', 'taken@example.com', '2026-01-01 00:00:00.000000', 'individual', 1);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteRecoveryEmailStore(connections);
            var now = DateTime.UtcNow;
            var requestId = await store.SubmitAsync(
                2, "alice.recovery@example.com", "alice.recovery@example.com", now, CancellationToken.None);
            await Assert.ThrowsAsync<RecoveryEmailException>(() => store.SubmitAsync(
                2, "another@example.com", "another@example.com", now, CancellationToken.None));
            await Assert.ThrowsAsync<RecoveryEmailException>(() => store.SubmitAsync(
                2, "taken@example.com", "taken@example.com", now, CancellationToken.None));
            var pending = Assert.Single(await store.ListPendingAsync(CancellationToken.None));
            Assert.Equal(requestId, pending.Id);
            Assert.Equal("alice.recovery@example.com", pending.RequestedEmail);

            var tokenHash = CapabilityTokenHash.Sha256("initial-email-verification");
            await Assert.ThrowsAsync<RecoveryEmailException>(() => store.ReviewAsync(
                requestId, 2, true, "Self review", tokenHash, now, CancellationToken.None));
            var approved = await store.ReviewAsync(
                requestId, 1, true, "Identity verified", tokenHash, now, CancellationToken.None);
            Assert.Equal("pending_verification", approved.Status);
            Assert.Equal("alice.recovery@example.com", approved.Email);
            await Assert.ThrowsAsync<RecoveryEmailException>(() => store.ResendAsync(
                2, CapabilityTokenHash.Sha256("too-soon"), now.AddMinutes(1), now.AddHours(25), CancellationToken.None));

            var replacementHash = CapabilityTokenHash.Sha256("replacement-email-verification");
            var resent = await store.ResendAsync(
                2, replacementHash, now.AddMinutes(6), now.AddHours(24).AddMinutes(6), CancellationToken.None);
            Assert.Equal("alice", resent.Username);
            Assert.Equal("alice.recovery@example.com", resent.Email);
            Assert.False(await store.VerifyAsync(tokenHash, now.AddMinutes(7), CancellationToken.None));
            Assert.True(await store.VerifyAsync(replacementHash, now.AddMinutes(7), CancellationToken.None));
            Assert.False(await store.VerifyAsync(replacementHash, now.AddMinutes(8), CancellationToken.None));

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = """
                SELECT user.email, user.email_normalized, user.email_verified_at,
                       request.status, request.verification_token_hash
                FROM users AS user
                JOIN email_change_requests AS request ON request.user_id = user.id
                WHERE user.id = 2 AND request.id = $request_id
                """;
            command.Parameters.AddWithValue("$request_id", requestId);
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("alice.recovery@example.com", reader.GetString(0));
            Assert.Equal("alice.recovery@example.com", reader.GetString(1));
            Assert.False(reader.IsDBNull(2));
            Assert.Equal("completed", reader.GetString(3));
            Assert.True(reader.IsDBNull(4));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
