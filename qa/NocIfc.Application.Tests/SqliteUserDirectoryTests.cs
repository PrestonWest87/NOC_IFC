using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteUserDirectoryTests
{
    [Fact]
    public async Task ReturnsSanitizedUsersWithRecoveryAndInvitationState()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-users-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY, username TEXT, full_name TEXT, job_title TEXT,
                        contact_info TEXT, email TEXT, email_verified_at TEXT, account_type TEXT,
                        role TEXT, is_active INTEGER, created_at TEXT, last_login_at TEXT, last_activity_at TEXT
                    );
                    CREATE TABLE email_change_requests (
                        id INTEGER PRIMARY KEY, user_id INTEGER, requested_email TEXT, status TEXT
                    );
                    CREATE TABLE registration_invites (
                        id INTEGER PRIMARY KEY, username TEXT, used_at TEXT, revoked_at TEXT, expires_at TEXT
                    );
                    INSERT INTO users VALUES
                        (1, 'alice', 'Alice', 'Operator', '555-0100', 'alice@example.com', NULL,
                         'individual', 'analyst', 1, '2026-01-02 03:04:05.000000', NULL, NULL),
                        (2, 'bob', NULL, NULL, NULL, NULL, NULL,
                         'individual', 'viewer', 1, NULL, NULL, NULL),
                        (3, 'display', 'Wall Screen', NULL, NULL, NULL, NULL,
                         'display', 'viewer', 0, NULL, NULL, NULL),
                        (4, 'verified', NULL, NULL, NULL, 'verified@example.com', '2026-01-01 00:00:00.000000',
                         'individual', 'analyst', 1, NULL, NULL, NULL);
                    INSERT INTO email_change_requests VALUES
                        (1, 1, 'alice.new@example.com', 'pending_review');
                    INSERT INTO registration_invites VALUES
                        (1, 'ALICE', NULL, NULL, strftime('%Y-%m-%d %H:%M:%f', 'now', '+1 hour')),
                        (2, 'bob', NULL, NULL, '2000-01-01 00:00:00.000000'),
                        (3, 'display', NULL, '2026-01-01 00:00:00.000000', '2099-01-01 00:00:00.000000');
                    """;
                await command.ExecuteNonQueryAsync();
            }

            var result = await new SqliteUserDirectory(connections).GetAllAsync(CancellationToken.None);

            Assert.Equal(new[] { "alice", "bob", "display", "verified" }, result.Select(user => user.Username));
            Assert.Equal("pending_approval", result[0].EmailStatus);
            Assert.Equal("alice.new@example.com", result[0].PendingEmail);
            Assert.True(result[0].InvitationPending);
            Assert.Equal("missing", result[1].EmailStatus);
            Assert.False(result[1].InvitationPending);
            Assert.Equal("exempt", result[2].EmailStatus);
            Assert.False(result[2].IsActive);
            Assert.Equal("verified", result[3].EmailStatus);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
