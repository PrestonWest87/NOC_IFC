using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Reporting;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class DailyFusionBroadcastCommandsTests
{
    [Fact]
    public async Task SendsNormalizedRecipientsAsSafeHtml()
    {
        var sender = new StubEmailSender();
        var commands = new DailyFusionBroadcastCommands(sender);

        var result = await commands.BroadcastAsync(
            "Thursday, November 26, 2026",
            "# Daily Brief\n\n- **Threat:** <script>alert(1)</script>",
            " first@example.test;second@example.test ",
            CancellationToken.None);

        Assert.True(result.Success);
        var call = Assert.Single(sender.HtmlCalls);
        Assert.Equal("first@example.test, second@example.test", call.Recipients);
        Assert.Equal("Daily Fusion Report - Thursday, November 26, 2026", call.Subject);
        Assert.Contains("NOC Daily Fusion Report", call.Body);
        Assert.Contains("<h1", call.Body);
        Assert.Contains("<strong>Threat:</strong>", call.Body);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", call.Body);
        Assert.DoesNotContain("<script>", call.Body);
    }

    [Fact]
    public async Task RejectsInvalidRecipientsAndSkipsEmptyRecipientDelivery()
    {
        var sender = new StubEmailSender();
        var commands = new DailyFusionBroadcastCommands(sender);

        var noRecipients = await commands.BroadcastAsync("date", "content", " ; , ", CancellationToken.None);
        Assert.False(noRecipients.Success);
        Assert.Equal("No recipients specified.", noRecipients.Message);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastAsync("date", "content", "valid@example.test\r\nBcc:other@example.test", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastAsync("date", "content", "not-an-email", CancellationToken.None));
        var tooMany = string.Join(",", Enumerable.Range(1, 21).Select(index => $"user{index}@example.test"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastAsync("date", "content", tooMany, CancellationToken.None));
        Assert.Empty(sender.HtmlCalls);
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public List<(string Recipients, string Subject, string Body)> HtmlCalls { get; } = [];

        public Task<EmailSendResult> SendPlainTextAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken) =>
            Task.FromResult(new EmailSendResult(true, "plain sent"));

        public Task<EmailSendResult> SendHtmlAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken)
        {
            HtmlCalls.Add((recipientOverride, subject, body));
            return Task.FromResult(new EmailSendResult(true, "HTML sent."));
        }
    }
}
