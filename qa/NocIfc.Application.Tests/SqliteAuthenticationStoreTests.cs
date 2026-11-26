using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Infrastructure.Security;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAuthenticationStoreTests
{
    private const string PythonBcryptHash = "$2b$04$0nVrv8HTA99lGMsDPALhUeDuvupAJyGHc/ctBUpsRUFszYNf2IwK6";
    private const string TestPassword = "NocIfc login compatibility test";

    [Fact]
    public async Task LoginVerifiesPythonBcryptHashAndPersistsSessionAndRecoveryState()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-login-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT, is_active INTEGER,
                        session_token TEXT, full_name TEXT, job_title TEXT, contact_info TEXT, default_shift TEXT, theme TEXT,
                        account_type TEXT, email TEXT, email_normalized TEXT, email_verified_at TEXT,
                        created_at TEXT, last_login_at TEXT, last_activity_at TEXT
                    );
                    CREATE TABLE user_sessions (
                        id INTEGER PRIMARY KEY, user_id INTEGER, token TEXT, created_at TEXT
                    );
                    CREATE TABLE roles (
                        id INTEGER PRIMARY KEY, name TEXT, allowed_pages TEXT, allowed_actions TEXT, allowed_site_types TEXT
                    );
                    CREATE TABLE email_change_requests (
                        id INTEGER PRIMARY KEY, user_id INTEGER, requested_email TEXT, status TEXT, requested_at TEXT
                    );
                    INSERT INTO roles VALUES (1, 'analyst', '["Threat Telemetry"]', '["Action: Pin Articles"]', '["NOC"]');
                    INSERT INTO users VALUES (
                        1, 'alice', $password_hash,
                        'analyst', 1, 'legacy-token', 'Alice', 'Operator', '555-0100', 'Night', 'standard',
                        'individual', 'alice@example.com', 'alice@example.com', NULL,
                        '2026-01-01 00:00:00.000000', NULL, NULL
                    );
                    INSERT INTO users VALUES (
                        2, 'disabled', $password_hash,
                        'analyst', 0, NULL, NULL, NULL, NULL, 'No Shift', 'standard',
                        'individual', NULL, NULL, NULL, '2026-01-01 00:00:00.000000', NULL, NULL
                    );
                    INSERT INTO email_change_requests VALUES
                        (1, 1, 'alice.pending@example.com', 'pending_review', '2026-01-02 00:00:00.000000');
                    """;
                setup.Parameters.AddWithValue("$password_hash", PythonBcryptHash);
                await setup.ExecuteNonQueryAsync();
            }

            var authentication = new AuthenticationService(
                new SqliteAuthenticationStore(connections),
                new BCryptPasswordVerifier(),
                new BCryptPasswordHasher(),
                new SiteTypeQueries(new StubSiteTypeDirectory(["NOC"])));

            var login = await authentication.AuthenticateAsync("alice", TestPassword, CancellationToken.None);
            var wrongPassword = await authentication.AuthenticateAsync("alice", "wrong password", CancellationToken.None);
            var disabled = await authentication.AuthenticateAsync("disabled", TestPassword, CancellationToken.None);

            Assert.NotNull(login);
            Assert.True(Guid.TryParse(login.Token, out _));
            Assert.Equal("Alice", login.User.FullName);
            Assert.Equal("pending_approval", login.User.RecoveryEmailStatus);
            Assert.Equal("alice.pending@example.com", login.User.PendingEmail);
            Assert.Equal(new[] { "Threat Telemetry" }, login.User.AllowedPages);
            Assert.NotNull(login.User.LastLoginAt);
            Assert.NotNull(login.User.LastActivityAt);
            Assert.Null(wrongPassword);
            Assert.Null(disabled);

            var currentUser = await authentication.GetCurrentUserAsync(login.User.Id, CancellationToken.None);
            Assert.Equal("pending_approval", currentUser?.RecoveryEmailStatus);
            await authentication.UpdateThemeAsync(login.User.Id, "cyberpunk", CancellationToken.None);
            Assert.Equal("cyberpunk", (await authentication.GetCurrentUserAsync(login.User.Id, CancellationToken.None))?.Theme);
            await Assert.ThrowsAsync<ArgumentException>(() =>
                authentication.UpdateThemeAsync(login.User.Id, "not-a-theme", CancellationToken.None));

            await Assert.ThrowsAsync<ArgumentException>(() => authentication.UpdateProfileAsync(
                login.User.Id, "Changed Name", "Operator", "555-0100", "Night", "incorrect",
                "NocIfc updated password 2026", CancellationToken.None));
            Assert.Equal("Alice", (await authentication.GetCurrentUserAsync(login.User.Id, CancellationToken.None))?.FullName);
            await Assert.ThrowsAsync<ArgumentException>(() => authentication.UpdateProfileAsync(
                login.User.Id, "Changed Name", "Operator", "555-0100", "Night", TestPassword,
                "short", CancellationToken.None));
            await authentication.UpdateProfileAsync(
                login.User.Id, " Alice Updated ", " Operator ", " 555-0101 ", " Day ", TestPassword,
                "NocIfc updated password 2026", CancellationToken.None);
            var updatedProfile = await authentication.GetCurrentUserAsync(login.User.Id, CancellationToken.None);
            Assert.Equal("Alice Updated", updatedProfile?.FullName);
            Assert.Equal("555-0101", updatedProfile?.ContactInfo);
            Assert.Null(await authentication.AuthenticateAsync("alice", TestPassword, CancellationToken.None));
            var passwordLogin = await authentication.AuthenticateAsync(
                "alice", "NocIfc updated password 2026", CancellationToken.None);
            Assert.NotNull(passwordLogin);
            await authentication.RevokeSessionAsync(login.User.Id, passwordLogin.Token, CancellationToken.None);
            await authentication.RevokeSessionAsync(login.User.Id, login.Token, CancellationToken.None);

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = """
                SELECT u.last_login_at, u.last_activity_at, u.session_token,
                       (SELECT COUNT(*) FROM user_sessions WHERE user_id = u.id),
                       (SELECT COUNT(*) FROM user_sessions WHERE user_id = 2)
                FROM users AS u WHERE u.id = 1
                """;
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.False(reader.IsDBNull(0));
            Assert.False(reader.IsDBNull(1));
            Assert.Equal("legacy-token", reader.GetString(2));
            Assert.Equal(0, reader.GetInt32(3));
            Assert.Equal(0, reader.GetInt32(4));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private sealed class StubSiteTypeDirectory(IReadOnlyList<string> siteTypes) : ISiteTypeDirectory
    {
        public Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(siteTypes);
    }
}
