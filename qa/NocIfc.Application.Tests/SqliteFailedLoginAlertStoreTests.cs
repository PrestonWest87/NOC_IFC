using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteFailedLoginAlertStoreTests
{
    [Fact]
    public async Task RecordsSanitizedAttemptsAndClaimsOnlyOneAlertPerWindow()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-failed-login-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE system_config (
                        id INTEGER PRIMARY KEY, failed_login_alert_enabled INTEGER,
                        failed_login_alert_recipients TEXT, failed_login_alert_threshold INTEGER,
                        failed_login_alert_window_minutes INTEGER, failed_login_alert_last_sent TEXT
                    );
                    CREATE TABLE failed_login_attempts (
                        id INTEGER PRIMARY KEY, username TEXT, source_ip TEXT, attempted_at TEXT
                    );
                    INSERT INTO system_config VALUES (
                        1, 1, 'security@example.com; SECURITY@example.com, noc@example.com', 3, 5, NULL
                    );
                    INSERT INTO failed_login_attempts VALUES (1, 'expired', NULL, '2000-01-01 00:00:00.000000');
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteFailedLoginAlertStore(connections);
            Assert.Null(await store.RecordAsync("one", "192.0.2.1", CancellationToken.None));
            Assert.Null(await store.RecordAsync("two", "bad-ip", CancellationToken.None));
            var alert = await store.RecordAsync(" bad\nname ", "192.0.2.3", CancellationToken.None);
            var throttled = await store.RecordAsync("four", null, CancellationToken.None);

            Assert.NotNull(alert);
            Assert.Equal("security@example.com, noc@example.com", alert.Recipients);
            Assert.Equal(3, alert.Threshold);
            Assert.Equal(5, alert.WindowMinutes);
            Assert.Equal(" bad name ", alert.Attempts[2].Username);
            Assert.Null(alert.Attempts[1].SourceIp);
            Assert.Null(throttled);

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using var command = verify.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM failed_login_attempts WHERE username = 'expired' OR username = 'four'";
            Assert.Equal(1L, await command.ExecuteScalarAsync());
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
