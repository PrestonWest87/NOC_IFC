using System.Text.Json;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteDisplayAccountStoreTests
{
    [Fact]
    public async Task CreatesEmailOptionalDisplayAccountAndAuditAtomically()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-display-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT,
                        full_name TEXT, default_shift TEXT, theme TEXT, account_type TEXT,
                        is_active INTEGER, created_at TEXT, email TEXT, email_normalized TEXT
                    );
                    CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT);
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT, event_detail TEXT, created_at TEXT
                    );
                    INSERT INTO users (id, username, role, is_active) VALUES (1, 'admin', 'admin', 1);
                    INSERT INTO roles VALUES (1, 'viewer');
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteUserAdminStore(connections);
            var created = await store.CreateDisplayAccountAsync(
                "wall-screen", "bcrypt-hash", "viewer", "HQ Wall Screen", 1, DateTime.UtcNow, CancellationToken.None);
            var duplicate = await store.CreateDisplayAccountAsync(
                "WALL-SCREEN", "bcrypt-hash", "viewer", "", 1, DateTime.UtcNow, CancellationToken.None);
            var missingRole = await store.CreateDisplayAccountAsync(
                "other-screen", "bcrypt-hash", "missing", "", 1, DateTime.UtcNow, CancellationToken.None);

            Assert.Equal(DisplayAccountCreateStatus.Created, created.Status);
            Assert.NotNull(created.UserId);
            Assert.Equal(DisplayAccountCreateStatus.UsernameTaken, duplicate.Status);
            Assert.Equal(DisplayAccountCreateStatus.RoleNotFound, missingRole.Status);

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var account = verify.CreateCommand();
            account.CommandText = "SELECT password_hash, role, full_name, default_shift, theme, account_type, is_active, email FROM users WHERE username='wall-screen'";
            await using var reader = await account.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("bcrypt-hash", reader.GetString(0));
            Assert.Equal("viewer", reader.GetString(1));
            Assert.Equal("HQ Wall Screen", reader.GetString(2));
            Assert.Equal("No Shift", reader.GetString(3));
            Assert.Equal("standard", reader.GetString(4));
            Assert.Equal("display", reader.GetString(5));
            Assert.True(reader.GetBoolean(6));
            Assert.True(reader.IsDBNull(7));
            await reader.DisposeAsync();

            await using var audit = verify.CreateCommand();
            audit.CommandText = "SELECT actor_user_id, subject_user_id, event_type, event_detail FROM account_audit_events";
            await using var auditReader = await audit.ExecuteReaderAsync();
            Assert.True(await auditReader.ReadAsync());
            Assert.Equal(1, auditReader.GetInt32(0));
            Assert.Equal(created.UserId, auditReader.GetInt32(1));
            Assert.Equal("display_account_created", auditReader.GetString(2));
            using var detail = JsonDocument.Parse(auditReader.GetString(3));
            Assert.Equal("viewer", detail.RootElement.GetProperty("role").GetString());
            Assert.False(await auditReader.ReadAsync());
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
