using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteOperationalIntegrationSettingsStoreTests
{
    [Fact]
    public async Task MergesEnvironmentAndDatabaseValuesWithoutReturningElasticSecret()
    {
        var (databasePath, connections) = await CreateDatabaseAsync();
        try
        {
            var environment = EnvironmentSettings();
            var store = new SqliteOperationalIntegrationSettingsStore(connections, environment);
            var settings = await store.GetAsync(CancellationToken.None);

            Assert.Equal("environment-risk@example.com", settings.RiskAlertRecipients);
            Assert.Equal("database-ticket@example.com", settings.RemedyforceTicketEmail);
            Assert.Equal("", settings.ElasticUrl);
            Assert.False(settings.ElasticApiKeyConfigured);
            Assert.False(settings.ElasticVerifyCerts);
            Assert.Equal("/environment/ca.pem", settings.ElasticCaCerts);
            Assert.Equal(30d, settings.ElasticRequestTimeout);
            Assert.Equal(1000, settings.ElasticMaxResults);
            Assert.Equal("", settings.CrimeAlertSms);
            Assert.Equal("environment-crime@example.com", settings.CrimeAlertEmail);
            Assert.Equal("environment", settings.Sources["risk_alert_recipients"]);
            Assert.Equal("database", settings.Sources["elastic_url"]);
            Assert.Equal("database", settings.Sources["elastic_api_key"]);

            var clientSettings = await store.GetElasticClientSettingsAsync(CancellationToken.None);
            Assert.Equal("", clientSettings.Endpoint);
            Assert.Equal("", clientSettings.ApiKey);
            Assert.False(clientSettings.VerifyCertificates);
            Assert.Equal("/environment/ca.pem", clientSettings.CaCertificates);
            Assert.Equal(30d, clientSettings.RequestTimeoutSeconds);
            Assert.Equal(1000, clientSettings.MaxResults);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task SavesExplicitEnvironmentResetAndAuditsFieldNamesWithoutSecretValues()
    {
        var (databasePath, connections) = await CreateDatabaseAsync();
        try
        {
            var store = new SqliteOperationalIntegrationSettingsStore(connections, EnvironmentSettings());
            var update = new OperationalIntegrationSettingsUpdate(
                null, null, null, null, null, null, "sensitive-elastic-key", null, null, null, null, null, null,
                new HashSet<string>(["elastic_api_key", "elastic_url"], StringComparer.Ordinal));
            await store.SaveAsync(update, 17, CancellationToken.None);

            var effective = await store.GetAsync(CancellationToken.None);
            Assert.Equal("https://environment-elastic.example.com", effective.ElasticUrl);
            Assert.Equal("environment", effective.Sources["elastic_url"]);
            Assert.True(effective.ElasticApiKeyConfigured);
            var clientSettings = await store.GetElasticClientSettingsAsync(CancellationToken.None);
            Assert.Equal("https://environment-elastic.example.com", clientSettings.Endpoint);
            Assert.Equal("sensitive-elastic-key", clientSettings.ApiKey);

            await using var connection = connections.Create();
            await connection.OpenAsync();
            await using var audit = connection.CreateCommand();
            audit.CommandText = "SELECT actor_user_id, event_type, event_detail FROM account_audit_events";
            await using var reader = await audit.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(17, reader.GetInt32(0));
            Assert.Equal("operational_settings_changed", reader.GetString(1));
            var details = reader.GetString(2);
            Assert.Contains("elastic_api_key", details, StringComparison.Ordinal);
            Assert.Contains("elastic_url", details, StringComparison.Ordinal);
            Assert.DoesNotContain("sensitive-elastic-key", details, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static IntegrationEnvironmentSettings EnvironmentSettings() => new(
        "environment-risk@example.com",
        "environment-ticket@example.com",
        "environment-noc@example.com",
        "environment-onpage@example.com",
        "environment-itnetwork@example.com",
        "https://environment-elastic.example.com",
        "environment-elastic-key",
        true,
        "/environment/ca.pem",
        15,
        500,
        "environment-sms@example.com",
        "environment-crime@example.com");

    private static async Task<(string DatabasePath, SqliteConnectionFactory Connections)> CreateDatabaseAsync()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-integrations-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await using var connection = connections.Create();
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
                risk_alert_recipients TEXT,
                remedyforce_ticket_email TEXT,
                noc_notify_email TEXT,
                noc_onpage_email TEXT,
                itnetwork_onpage_email TEXT,
                elastic_url TEXT,
                elastic_api_key TEXT,
                elastic_verify_certs INTEGER,
                elastic_ca_certs TEXT,
                elastic_request_timeout REAL,
                elastic_max_results INTEGER,
                crime_alert_sms TEXT,
                crime_alert_email TEXT
            );
            INSERT INTO system_config (
                llm_provider, active_smtp_provider, gmail_smtp_enabled,
                failed_login_alert_enabled, failed_login_alert_recipients,
                failed_login_alert_threshold, failed_login_alert_window_minutes,
                permission_catalog_version, scheduler_revision, scheduler_applied_revision,
                remedyforce_ticket_email, elastic_url, elastic_api_key, elastic_verify_certs,
                elastic_request_timeout, elastic_max_results, crime_alert_sms
            ) VALUES (
                'openai_compatible', 'smtp', 0, 0, '', 5, 5, 0, 0, 0,
                'database-ticket@example.com', '', '', 0, 30, 1000, ''
            );
            CREATE TABLE account_audit_events (
                id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                event_type TEXT NOT NULL, event_detail TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """;
        await setup.ExecuteNonQueryAsync();
        return (databasePath, connections);
    }
}
