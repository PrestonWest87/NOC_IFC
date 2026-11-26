using System.Text.Json;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteUserAdminStoreTests
{
    [Fact]
    public async Task UserMutationsRevokeSessionsAndWriteAuditInTheSameTransaction()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-user-admin-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, username TEXT, role TEXT, is_active INTEGER,
                        session_token TEXT, account_type TEXT, email TEXT, email_verified_at TEXT,
                        password_hash TEXT, full_name TEXT, job_title TEXT, contact_info TEXT
                    );
                    CREATE TABLE user_sessions (id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT);
                    CREATE TABLE password_reset_tokens (id INTEGER PRIMARY KEY, user_id INTEGER, used_at TEXT);
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at TEXT
                    );
                    INSERT INTO users VALUES (
                        1, 'operator', 'analyst', 1, 'legacy-token', 'individual', NULL, NULL,
                        'old-hash', 'Initial Name', 'Operator', '555-0100'
                    );
                    INSERT INTO user_sessions VALUES (1, 1, 'modern-token');
                    INSERT INTO password_reset_tokens VALUES (1, 1, NULL);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteUserAdminStore(connections);
            var target = await store.FindTargetAsync("operator", CancellationToken.None);
            Assert.NotNull(target);
            Assert.True(await store.UpdateIdentityAsync(target, "Updated Name", "Network Operator", "555-0101", 9, CancellationToken.None));
            Assert.True(await store.SetAccountTypeAsync(target, "display", 9, DateTime.UtcNow, CancellationToken.None));
            Assert.True(await store.ChangeRoleAsync(target, "viewer", 9, CancellationToken.None));
            var displayTarget = target with { Role = "viewer", AccountType = "display" };
            Assert.True(await store.SetActiveAsync(displayTarget, false, 9, CancellationToken.None));
            Assert.True(await store.SetActiveAsync(displayTarget, true, 9, CancellationToken.None));
            Assert.True(await store.RevokeSessionsAsync(displayTarget, 9, CancellationToken.None));
            Assert.True(await store.AdministratorResetAsync(
                displayTarget, "new-password-hash", 9, DateTime.UtcNow, CancellationToken.None));

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = """
                SELECT u.role, u.is_active, u.session_token, u.password_hash, u.account_type,
                       u.full_name, u.job_title, u.contact_info,
                       (SELECT COUNT(*) FROM user_sessions WHERE user_id = u.id),
                       (SELECT COUNT(*) FROM account_audit_events WHERE subject_user_id = u.id),
                       (SELECT used_at FROM password_reset_tokens WHERE user_id = u.id)
                FROM users AS u WHERE u.id = 1
                """;
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("viewer", reader.GetString(0));
            Assert.True(reader.GetBoolean(1));
            Assert.True(reader.IsDBNull(2));
            Assert.Equal("new-password-hash", reader.GetString(3));
            Assert.Equal("display", reader.GetString(4));
            Assert.Equal("Updated Name", reader.GetString(5));
            Assert.Equal("Network Operator", reader.GetString(6));
            Assert.Equal("555-0101", reader.GetString(7));
            Assert.Equal(0, reader.GetInt32(8));
            Assert.Equal(7, reader.GetInt32(9));
            Assert.False(reader.IsDBNull(10));
            await reader.DisposeAsync();

            await using var audit = verify.CreateCommand();
            audit.CommandText = "SELECT event_type, event_detail FROM account_audit_events ORDER BY id";
            await using var auditReader = await audit.ExecuteReaderAsync();
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("user_profile_updated", auditReader.GetString(0));
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("account_type_changed", auditReader.GetString(0));
            using var accountTypeDetail = JsonDocument.Parse(auditReader.GetString(1));
            Assert.Equal("individual", accountTypeDetail.RootElement.GetProperty("from").GetString());
            Assert.Equal("display", accountTypeDetail.RootElement.GetProperty("to").GetString());
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("user_role_changed", auditReader.GetString(0));
            using var detail = JsonDocument.Parse(auditReader.GetString(1));
            Assert.Equal("analyst", detail.RootElement.GetProperty("from").GetString());
            Assert.Equal("viewer", detail.RootElement.GetProperty("to").GetString());
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("user_disabled", auditReader.GetString(0));
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("user_activated", auditReader.GetString(0));
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("user_sessions_revoked", auditReader.GetString(0));
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal("administrator_password_reset", auditReader.GetString(0));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
