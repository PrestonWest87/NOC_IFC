using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class SqliteUserSessionResolverTests
{
    [Fact]
    public async Task ResolvesActiveAndLegacySessionsWithRoleGrants()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"noc-ifc-session-{Guid.NewGuid():N}.sqlite");
        try
        {
            await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY,
                        username TEXT NOT NULL,
                        role TEXT,
                        is_active INTEGER NOT NULL,
                        session_token TEXT,
                        last_activity_at TEXT
                    );
                    CREATE TABLE user_sessions (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        token TEXT NOT NULL
                    );
                    CREATE TABLE roles (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        allowed_pages TEXT,
                        allowed_actions TEXT,
                        allowed_site_types TEXT
                    );
                    INSERT INTO roles VALUES (
                        1, 'analyst', '["Threat Telemetry"]', '["Action: Pin Articles"]', '["NOC"]');
                    INSERT INTO roles VALUES (2, 'admin', '[]', '[]', '[]');
                    INSERT INTO users VALUES (1, 'operator', 'analyst', 1, 'legacy-token', NULL);
                    INSERT INTO user_sessions VALUES (1, 1, 'active-token');
                    INSERT INTO users VALUES (2, 'admin', 'admin', 1, NULL, NULL);
                    INSERT INTO user_sessions VALUES (2, 2, 'admin-token');
                    """;
                await command.ExecuteNonQueryAsync();
            }

            var resolver = new SqliteUserSessionResolver(
                new SqliteConnectionFactory($"sqlite:///{databasePath}"),
                new SiteTypeQueries(new StubSiteTypeDirectory(["Fiber Hut"])));

            var activeUser = await resolver.ResolveAsync("active-token", CancellationToken.None);
            var legacyUser = await resolver.ResolveAsync("legacy-token", CancellationToken.None);
            var unknownUser = await resolver.ResolveAsync("unknown-token", CancellationToken.None);
            var adminUser = await resolver.ResolveAsync("admin-token", CancellationToken.None);
            var roles = await new SqliteRoleDirectory(new SqliteConnectionFactory($"sqlite:///{databasePath}"))
                .GetAllAsync(CancellationToken.None);

            Assert.Equal("operator", activeUser?.Username);
            Assert.Equal(new[] { "Threat Telemetry" }, activeUser?.AllowedPages);
            Assert.Equal(new[] { "Action: Pin Articles" }, activeUser?.AllowedActions);
            Assert.Equal(new[] { "NOC" }, activeUser?.AllowedSiteTypes);
            Assert.Equal("operator", legacyUser?.Username);
            Assert.Null(unknownUser);
            Assert.Contains("Settings & Admin", adminUser!.AllowedPages);
            Assert.Contains("Action: Manage Roles", adminUser.AllowedActions);
            Assert.Contains("Fiber Hut", adminUser.AllowedSiteTypes);
            Assert.Equal(new[] { "analyst", "admin" }, roles.Select(role => role.Name));

            await using var verification = new SqliteConnection($"Data Source={databasePath}");
            await verification.OpenAsync();
            await using var query = verification.CreateCommand();
            query.CommandText = "SELECT last_activity_at FROM users WHERE id = 1";
            Assert.False(string.IsNullOrWhiteSpace(Convert.ToString(await query.ExecuteScalarAsync())));
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
