using System.Text.Json;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteInvitationStoreTests
{
    [Fact]
    public async Task CreatesListsReplacesAndRevokesInvitationsWithAudit()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-invites-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email_normalized TEXT);
                    CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT);
                    CREATE TABLE email_change_requests (
                        id INTEGER PRIMARY KEY, requested_email_normalized TEXT, status TEXT
                    );
                    CREATE TABLE registration_invites (
                        id INTEGER PRIMARY KEY, username TEXT, role TEXT, token_hash TEXT, created_by TEXT,
                        created_at TEXT, expires_at TEXT, used_at TEXT, revoked_at TEXT,
                        email TEXT, email_normalized TEXT, account_type TEXT
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at TEXT
                    );
                    CREATE TABLE system_config (id INTEGER PRIMARY KEY, public_app_url TEXT);
                    INSERT INTO users VALUES (1, 'alice', 'alice@example.com');
                    INSERT INTO roles VALUES (1, 'analyst');
                    INSERT INTO email_change_requests VALUES (1, 'pending@example.com', 'pending_review');
                    INSERT INTO registration_invites VALUES (
                        1, 'other-user', 'analyst', 'existing-hash', 'admin',
                        '2026-01-01 00:00:00.000000', '2099-01-01 00:00:00.000000', NULL, NULL,
                        'Occupied@example.com', 'occupied@example.com', 'individual'
                    );
                    INSERT INTO system_config VALUES (1, 'https://ifc.example.com/');
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteUserAdminStore(connections);
            var now = DateTime.UtcNow;
            var usernameExists = await store.CreateRegistrationInviteAsync(
                "alice", "new@example.com", "new@example.com", "analyst", "hash-a", "admin", 72, now, CancellationToken.None);
            var emailInUse = await store.CreateRegistrationInviteAsync(
                "bob", "alice@example.com", "alice@example.com", "analyst", "hash-b", "admin", 72, now, CancellationToken.None);
            var emailPending = await store.CreateRegistrationInviteAsync(
                "carol", "pending@example.com", "pending@example.com", "analyst", "hash-c", "admin", 72, now, CancellationToken.None);
            var emailInvited = await store.CreateRegistrationInviteAsync(
                "dave", "occupied@example.com", "occupied@example.com", "analyst", "hash-d", "admin", 72, now, CancellationToken.None);
            var missingRole = await store.CreateRegistrationInviteAsync(
                "erin", "erin@example.com", "erin@example.com", "missing", "hash-e", "admin", 72, now, CancellationToken.None);

            Assert.Equal(RegistrationInviteCreateStatus.UsernameExists, usernameExists.Status);
            Assert.Equal(RegistrationInviteCreateStatus.EmailInUse, emailInUse.Status);
            Assert.Equal(RegistrationInviteCreateStatus.EmailPendingRecovery, emailPending.Status);
            Assert.Equal(RegistrationInviteCreateStatus.EmailHasPendingInvite, emailInvited.Status);
            Assert.Equal(RegistrationInviteCreateStatus.RoleNotFound, missingRole.Status);

            await using (var expire = connections.Create())
            {
                await expire.OpenAsync();
                await using var command = expire.CreateCommand();
                command.CommandText = "UPDATE registration_invites SET used_at = $now WHERE id = 1";
                command.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", System.Globalization.CultureInfo.InvariantCulture));
                await command.ExecuteNonQueryAsync();
            }

            var first = await store.CreateRegistrationInviteAsync(
                "new-user", "New.User@example.com", "new.user@example.com", "analyst", "hash-first", "admin", 72, now, CancellationToken.None);
            var replacement = await store.CreateRegistrationInviteAsync(
                "new-user", "New.User@example.com", "new.user@example.com", "analyst", "hash-second", "admin", 72, now, CancellationToken.None);
            Assert.Equal(RegistrationInviteCreateStatus.Created, first.Status);
            Assert.Equal(RegistrationInviteCreateStatus.Created, replacement.Status);

            var pending = await store.GetPendingInvitationsAsync(now, CancellationToken.None);
            var invitation = Assert.Single(pending);
            Assert.Equal(replacement.InviteId, invitation.Id);
            Assert.Equal("new-user", invitation.Username);
            Assert.Equal("New.User@example.com", invitation.Email);
            Assert.Equal("admin", invitation.CreatedBy);
            Assert.Equal("https://ifc.example.com/", await store.GetPublicAppUrlAsync(CancellationToken.None));

            Assert.True(await store.RevokeInvitationAsync(invitation.Id, 7, now, CancellationToken.None));
            Assert.Empty(await store.GetPendingInvitationsAsync(now, CancellationToken.None));

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var audit = verify.CreateCommand();
            audit.CommandText = "SELECT actor_user_id, subject_user_id, event_type, event_detail FROM account_audit_events";
            await using var reader = await audit.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(7, reader.GetInt32(0));
            Assert.True(reader.IsDBNull(1));
            Assert.Equal("registration_invite_revoked", reader.GetString(2));
            using var detail = JsonDocument.Parse(reader.GetString(3));
            Assert.Equal(invitation.Id, detail.RootElement.GetProperty("invite_id").GetInt32());
            Assert.Equal("new-user", detail.RootElement.GetProperty("username").GetString());
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
