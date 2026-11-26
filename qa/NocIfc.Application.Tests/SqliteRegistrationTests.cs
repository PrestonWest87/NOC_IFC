using System.Security.Cryptography;
using System.Text;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Infrastructure.Security;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteRegistrationTests
{
    [Fact]
    public async Task RegistrationValidatesAndConsumesHashedInviteWithVerifiedSession()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-registration-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        const string rawToken = "registration-token-once";
        var tokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))).ToLowerInvariant();
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
                        session_token TEXT, full_name TEXT, job_title TEXT, contact_info TEXT, default_shift TEXT,
                        theme TEXT, account_type TEXT, email TEXT, email_normalized TEXT, email_verified_at TEXT,
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
                    CREATE TABLE registration_invites (
                        id INTEGER PRIMARY KEY, username TEXT, role TEXT, token_hash TEXT, created_by TEXT,
                        created_at TEXT, expires_at TEXT, used_at TEXT, revoked_at TEXT,
                        email TEXT, email_normalized TEXT, account_type TEXT
                    );
                    INSERT INTO roles VALUES (1, 'analyst', '["Threat Telemetry"]', '["Action: Pin Articles"]', '["NOC"]');
                    INSERT INTO registration_invites VALUES (
                        1, 'bob', 'analyst', $token_hash, 'admin', '2026-01-01 00:00:00.000000',
                        '2099-01-01 00:00:00.000000', NULL, NULL,
                        'Bob.Example@example.com', 'bob.example@example.com', 'individual'
                    );
                    """;
                setup.Parameters.AddWithValue("$token_hash", tokenHash);
                await setup.ExecuteNonQueryAsync();
            }

            var authentication = new AuthenticationService(
                new SqliteAuthenticationStore(connections),
                new BCryptPasswordVerifier(),
                new BCryptPasswordHasher(),
                new SiteTypeQueries(new StubSiteTypeDirectory(["NOC"])));

            var invite = await authentication.GetRegistrationInviteAsync(rawToken, CancellationToken.None);
            Assert.NotNull(invite);
            Assert.Equal("bob", invite.Username);
            Assert.Equal("Bob.Example@example.com", invite.Email);
            Assert.Null(await authentication.GetRegistrationInviteAsync("wrong-token", CancellationToken.None));

            var registration = await authentication.CompleteRegistrationAsync(
                new RegistrationInput(
                    rawToken,
                    "Registration password 123",
                    " Bob Example ",
                    " Analyst ",
                    " ",
                    "No Shift",
                    "standard"),
                CancellationToken.None);

            Assert.Equal("bob", registration.User.Username);
            Assert.Equal("Bob Example", registration.User.FullName);
            Assert.Equal("individual", registration.User.AccountType);
            Assert.Equal("verified", registration.User.RecoveryEmailStatus);
            Assert.NotNull(registration.User.EmailVerifiedAt);
            Assert.Equal(new[] { "Threat Telemetry" }, registration.User.AllowedPages);
            Assert.Null(await authentication.GetRegistrationInviteAsync(rawToken, CancellationToken.None));
            await Assert.ThrowsAsync<RegistrationException>(() => authentication.CompleteRegistrationAsync(
                new RegistrationInput(rawToken, "Registration password 123", "", "", "", "No Shift", "standard"),
                CancellationToken.None));

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = """
                SELECT u.email, u.email_normalized, u.email_verified_at, u.session_token,
                       (SELECT COUNT(*) FROM user_sessions AS s WHERE s.user_id = u.id),
                       i.used_at, i.token_hash
                FROM users AS u
                JOIN registration_invites AS i ON i.username = u.username
                WHERE u.username = 'bob'
                """;
            await using var reader = await command.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal("Bob.Example@example.com", reader.GetString(0));
            Assert.Equal("bob.example@example.com", reader.GetString(1));
            Assert.False(reader.IsDBNull(2));
            Assert.Equal(registration.Token, reader.GetString(3));
            Assert.Equal(1, reader.GetInt32(4));
            Assert.False(reader.IsDBNull(5));
            Assert.Equal(tokenHash, reader.GetString(6));
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
