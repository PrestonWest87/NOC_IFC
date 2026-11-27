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
        var commands = new ReportingBroadcastCommands(sender);

        var result = await commands.BroadcastDailyFusionAsync(
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
        var commands = new ReportingBroadcastCommands(sender);

        var noRecipients = await commands.BroadcastDailyFusionAsync("date", "content", " ; , ", CancellationToken.None);
        Assert.False(noRecipients.Success);
        Assert.Equal("No recipients specified.", noRecipients.Message);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastDailyFusionAsync("date", "content", "valid@example.test\r\nBcc:other@example.test", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastDailyFusionAsync("date", "content", "not-an-email", CancellationToken.None));
        var tooMany = string.Join(",", Enumerable.Range(1, 21).Select(index => $"user{index}@example.test"));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            commands.BroadcastDailyFusionAsync("date", "content", tooMany, CancellationToken.None));
        Assert.Empty(sender.HtmlCalls);
    }

    [Fact]
    public async Task BroadcastsCustomReportWithEscapedTitleAndCentralGenerationTime()
    {
        var sender = new StubEmailSender();
        var commands = new ReportingBroadcastCommands(sender);

        var result = await commands.BroadcastCustomAsync(
            "  <Quarterly Ops>  ",
            "## Risk\n\n- **Impact:** <script>untrusted</script>",
            "ops@example.test",
            CancellationToken.None);

        Assert.True(result.Success);
        var call = Assert.Single(sender.HtmlCalls);
        Assert.Equal("<Quarterly Ops>", call.Subject);
        Assert.Contains("&lt;Quarterly Ops&gt;", call.Body);
        Assert.Contains("Generated:", call.Body);
        Assert.Contains("<h2", call.Body);
        Assert.Contains("<strong>Impact:</strong>", call.Body);
        Assert.Contains("&lt;script&gt;untrusted&lt;/script&gt;", call.Body);
        Assert.DoesNotContain("<script>", call.Body);
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

        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride,
            string subject,
            string body,
            IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken) =>
            SendHtmlAsync(recipientOverride, subject, body, cancellationToken);
    }
}
