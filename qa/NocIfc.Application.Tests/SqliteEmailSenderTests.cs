using NocIfc.Infrastructure.Email;
using NocIfc.Infrastructure.Persistence.Sqlite;
using NocIfc.Application.Abstractions.Email;
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
            var htmlResult = await sender.SendHtmlAsync(
                "security@example.com", "Test report", "<p>body</p>", CancellationToken.None);
            var attachmentResult = await sender.SendHtmlWithAttachmentsAsync(
                "security@example.com", "Test report", "<p>body</p>",
                [new NocIfc.Application.Abstractions.Email.EmailAttachment("weather.svg", "image/svg+xml", [1, 2, 3])],
                CancellationToken.None);
            var operationalResult = await sender.SendOperationalEmailAsync(
                new OperationalEmailEnvelope(
                    ["security@example.com"], ["noc@example.com"], ["audit@example.com"],
                    "Operational test", "Plain body", "<pre>Plain body</pre>", []),
                CancellationToken.None);
            var missingToResult = await sender.SendOperationalEmailAsync(
                new OperationalEmailEnvelope([], [], ["audit@example.com"], "No To", "Body", "<pre>Body</pre>", []),
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Equal("SMTP is disabled in Settings.", result.Message);
            Assert.False(htmlResult.Success);
            Assert.Equal("SMTP is disabled in Settings.", htmlResult.Message);
            Assert.False(attachmentResult.Success);
            Assert.Equal("SMTP is disabled in Settings.", attachmentResult.Message);
            Assert.False(operationalResult.Success);
            Assert.Equal("SMTP is disabled in Settings.", operationalResult.Message);
            Assert.False(missingToResult.Success);
            Assert.Equal("At least one To recipient is required.", missingToResult.Message);
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
