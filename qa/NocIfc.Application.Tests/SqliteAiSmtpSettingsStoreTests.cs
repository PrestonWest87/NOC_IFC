using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAiSmtpSettingsStoreTests
{
    [Fact]
    public async Task ReadsSecretsAsConfiguredFlagsAndPreservesUnspecifiedFieldsOnSave()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-ai-smtp-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, llm_endpoint TEXT, llm_api_key TEXT,
                        llm_model_name TEXT, llm_provider TEXT, is_active INTEGER,
                        llm_context_window INTEGER, active_smtp_provider TEXT,
                        smtp_enabled INTEGER, smtp_server TEXT, smtp_port INTEGER,
                        smtp_username TEXT, smtp_password TEXT, smtp_sender TEXT, smtp_recipient TEXT,
                        gmail_smtp_username TEXT, gmail_smtp_client_id TEXT,
                        gmail_smtp_client_secret TEXT, gmail_smtp_refresh_token TEXT,
                        gmail_smtp_sender TEXT, gmail_smtp_enabled INTEGER
                    );
                    INSERT INTO system_config VALUES (
                        1, 'https://api.example/v1', 'llm-secret', 'model-a', 'openai_compatible',
                        1, 128000, 'smtp', 1, 'smtp.example', 587, 'user', 'smtp-secret',
                        'noc@example.com', 'ops@example.com', 'gmail@example.com', 'gmail-id',
                        'gmail-secret', 'gmail-refresh', '', 1
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteAiSmtpSettingsStore(connections);
            var initial = Assert.IsType<AiSmtpSettings>(await store.GetAsync(CancellationToken.None));
            Assert.True(initial.LlmApiKeyConfigured);
            Assert.True(initial.SmtpPasswordConfigured);
            Assert.True(initial.GmailSmtpClientIdConfigured);
            Assert.True(initial.GmailSmtpClientSecretConfigured);
            Assert.True(initial.GmailSmtpRefreshTokenConfigured);

            var update = new AiSmtpSettingsUpdate(
                null, null, null, "ollama_native", null, null,
                null, null, "smtp-updated.example", null, null, null, null, null,
                null, null, null, null, null, null,
                new HashSet<string>(["llm_provider", "smtp_server"], StringComparer.Ordinal));
            await store.SaveAsync(update, CancellationToken.None);

            var after = Assert.IsType<AiSmtpSettings>(await store.GetAsync(CancellationToken.None));
            Assert.Equal("ollama_native", after.LlmProvider);
            Assert.False(after.LlmApiKeyConfigured);
            Assert.Equal("smtp-updated.example", after.SmtpServer);
            Assert.Equal("smtp", after.ActiveSmtpProvider);
            Assert.True(after.SmtpPasswordConfigured);
            Assert.True(after.GmailSmtpClientSecretConfigured);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
