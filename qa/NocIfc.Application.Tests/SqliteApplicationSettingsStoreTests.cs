using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteApplicationSettingsStoreTests
{
    [Fact]
    public async Task ReadsAndUpdatesGlobalSettingsAndChecksSelectedSenderReadiness()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-app-settings-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY,
                        llm_provider TEXT NOT NULL,
                        active_smtp_provider TEXT NOT NULL,
                        gmail_smtp_enabled INTEGER NOT NULL,
                        public_app_url TEXT,
                        tech_stack TEXT,
                        monitored_asns TEXT,
                        failed_login_alert_enabled INTEGER NOT NULL,
                        failed_login_alert_recipients TEXT NOT NULL,
                        failed_login_alert_threshold INTEGER NOT NULL,
                        failed_login_alert_window_minutes INTEGER NOT NULL,
                        permission_catalog_version INTEGER NOT NULL,
                        scheduler_revision INTEGER NOT NULL,
                        scheduler_applied_revision INTEGER NOT NULL,
                        gmail_smtp_username TEXT,
                        gmail_smtp_client_id TEXT,
                        gmail_smtp_client_secret TEXT,
                        gmail_smtp_refresh_token TEXT,
                        gmail_smtp_sender TEXT,
                        smtp_server TEXT,
                        smtp_sender TEXT,
                        smtp_enabled INTEGER
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteApplicationSettingsStore(connections);
            Assert.Null(await store.GetAsync(CancellationToken.None));
            Assert.False(await store.ActiveEmailProfileIsReadyAsync(CancellationToken.None));
            await store.SaveAsync(new GlobalApplicationSettingsUpdate(
                "https://noc.example.com", "SolarWinds", "AS701", false, "", 5, 5), CancellationToken.None);

            var settings = await store.GetAsync(CancellationToken.None);
            Assert.NotNull(settings);
            Assert.Equal("https://noc.example.com", settings.PublicAppUrl);
            Assert.Equal("SolarWinds", settings.TechStack);
            Assert.False(settings.FailedLoginAlertEnabled);
            Assert.False(await store.ActiveEmailProfileIsReadyAsync(CancellationToken.None));

            await using var updateConnection = connections.Create();
            await updateConnection.OpenAsync();
            await using var smtp = updateConnection.CreateCommand();
            smtp.CommandText = "UPDATE system_config SET smtp_enabled = 1, smtp_server = 'smtp.example.com', smtp_sender = 'noc@example.com'";
            await smtp.ExecuteNonQueryAsync();
            Assert.True(await store.ActiveEmailProfileIsReadyAsync(CancellationToken.None));
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
