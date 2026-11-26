using NocIfc.Infrastructure.Email;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteEmailSenderTests
{
    [Fact]
    public async Task DisabledSelectedProviderReturnsWithoutNetworkAccess()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-email-{Guid.NewGuid():N}.sqlite");
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
                        id INTEGER PRIMARY KEY, active_smtp_provider TEXT, smtp_server TEXT, smtp_port INTEGER,
                        smtp_username TEXT, smtp_password TEXT, smtp_sender TEXT, smtp_recipient TEXT,
                        smtp_enabled INTEGER, gmail_smtp_username TEXT, gmail_smtp_client_id TEXT,
                        gmail_smtp_client_secret TEXT, gmail_smtp_refresh_token TEXT, gmail_smtp_sender TEXT,
                        gmail_smtp_enabled INTEGER
                    );
                    INSERT INTO system_config VALUES (
                        1, 'smtp', 'smtp.example.com', 587, '', '', 'noc@example.com',
                        'security@example.com', 0, '', '', '', '', '', 0
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            using var http = new HttpClient(new ThrowIfCalledHandler());
            var sender = new SqliteEmailSender(connections, new GmailOAuthTokenProvider(http));
            var result = await sender.SendPlainTextAsync(
                "security@example.com", "Test alert", "body", CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal("SMTP is disabled in Settings.", result.Message);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private sealed class ThrowIfCalledHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No network request should occur for disabled SMTP.");
    }
}
