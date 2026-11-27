using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiSmtpSettingsCommandsTests
{
    [Fact]
    public async Task ValidatesProviderAndPersistsOnlyProvidedFields()
    {
        var store = new StubStore();
        var email = new StubEmailSender();
        var commands = new AiSmtpSettingsCommands(store, email);
        var update = EmptyUpdate() with
        {
            LlmProvider = " OLLAMA_NATIVE ",
            ActiveSmtpProvider = "gmail",
            GmailSmtpEnabled = true,
            GmailSmtpUsername = "noc@example.com",
            GmailSmtpClientId = "client-id",
            GmailSmtpClientSecret = "client-secret",
            GmailSmtpRefreshToken = "refresh-token",
            ProvidedFields = new HashSet<string>([
                "llm_provider", "active_smtp_provider", "gmail_smtp_enabled", "gmail_smtp_username",
                "gmail_smtp_client_id", "gmail_smtp_client_secret", "gmail_smtp_refresh_token",
            ], StringComparer.Ordinal),
        };

        await commands.SaveAsync(update, CancellationToken.None);

        Assert.NotNull(store.Saved);
        Assert.Equal("ollama_native", store.Saved.LlmProvider);
        Assert.Contains("llm_provider", store.Saved.ProvidedFields);
        Assert.DoesNotContain("smtp_server", store.Saved.ProvidedFields);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            EmptyUpdate() with
            {
                ActiveSmtpProvider = "invalid",
                ProvidedFields = new HashSet<string>(["active_smtp_provider"], StringComparer.Ordinal),
            },
            CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            EmptyUpdate() with
            {
                SmtpPort = 70000,
                ProvidedFields = new HashSet<string>(["smtp_port"], StringComparer.Ordinal),
            },
            CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            EmptyUpdate() with
            {
                ProvidedFields = new HashSet<string>(["unknown_setting"], StringComparer.Ordinal),
            },
            CancellationToken.None));
    }

    [Fact]
    public async Task TestEmailValidatesOneRecipientAndUsesTheActiveSender()
    {
        var email = new StubEmailSender();
        var commands = new AiSmtpSettingsCommands(new StubStore(), email);
        var result = await commands.SendTestEmailAsync(" noc@example.com ", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("noc@example.com", email.Recipient);
        Assert.Equal("SMTP configuration test", email.Subject);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.SendTestEmailAsync("one@example.com, two@example.com", CancellationToken.None));
    }

    private static AiSmtpSettingsUpdate EmptyUpdate() => new(
        null, null, null, null, null, null,
        null, null, null, null, null, null, null, null,
        null, null, null, null, null, null,
        new HashSet<string>(StringComparer.Ordinal));

    private sealed class StubStore : IAiSmtpSettingsStore
    {
        public AiSmtpSettingsUpdate? Saved { get; private set; }
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<AiSmtpSettings?>(null);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) =>
            Task.FromResult("saved-key");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken)
        {
            Saved = update;
            return Task.CompletedTask;
        }
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public string? Recipient { get; private set; }
        public string? Subject { get; private set; }

        public Task<EmailSendResult> SendPlainTextAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken)
        {
            Recipient = recipientOverride;
            Subject = subject;
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }

        public Task<EmailSendResult> SendHtmlAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken) =>
            SendPlainTextAsync(recipientOverride, subject, body, cancellationToken);
    }
}
