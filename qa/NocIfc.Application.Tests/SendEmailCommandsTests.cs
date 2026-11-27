using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Email;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SendEmailCommandsTests
{
    [Fact]
    public async Task DecodesAttachmentsAndSendsSanitizedHtmlEmail()
    {
        var sender = new StubEmailSender();
        var command = new SendEmailCommands(sender);
        var svg = "<svg/>"u8.ToArray();

        var result = await command.SendAsync(
            new SendEmailInput(
                "ops@example.test",
                "Weather Sitrep",
                "<p>Current posture</p>",
                [new SendEmailAttachmentInput("../weather-posture.svg", "image/svg+xml", Convert.ToBase64String(svg))]),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("ops@example.test", sender.Recipient);
        Assert.Equal("Weather Sitrep", sender.Subject);
        Assert.Equal("<p>Current posture</p>", sender.Body);
        var attachment = Assert.Single(sender.Attachments);
        Assert.Equal("weather-posture.svg", attachment.FileName);
        Assert.Equal("image/svg+xml", attachment.ContentType);
        Assert.Equal(svg, attachment.Content);
    }

    [Fact]
    public async Task RejectsInvalidAndOversizedAttachmentsBeforeCallingTheSender()
    {
        var sender = new StubEmailSender();
        var command = new SendEmailCommands(sender);

        var invalid = await command.SendAsync(
            new SendEmailInput("ops@example.test", "Report", "<p>body</p>",
                [new SendEmailAttachmentInput("weather.svg", "image/svg+xml", "%%%")]),
            CancellationToken.None);
        Assert.False(invalid.Success);
        Assert.Equal("Invalid email attachment: weather.svg", invalid.Message);

        var tooLargeBase64 = Convert.ToBase64String(new byte[5 * 1024 * 1024 + 1]);
        var tooLarge = await command.SendAsync(
            new SendEmailInput("ops@example.test", "Report", "<p>body</p>",
                [new SendEmailAttachmentInput("weather.svg", "image/svg+xml", tooLargeBase64)]),
            CancellationToken.None);
        Assert.False(tooLarge.Success);
        Assert.Equal("Email attachment too large: weather.svg", tooLarge.Message);
        Assert.Null(sender.Recipient);
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public string? Recipient { get; private set; }
        public string? Subject { get; private set; }
        public string? Body { get; private set; }
        public IReadOnlyList<EmailAttachment> Attachments { get; private set; } = [];

        public Task<EmailSendResult> SendPlainTextAsync(
            string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            Task.FromResult(new EmailSendResult(true, "sent"));

        public Task<EmailSendResult> SendHtmlAsync(
            string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            Task.FromResult(new EmailSendResult(true, "sent"));

        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride,
            string subject,
            string body,
            IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken)
        {
            Recipient = recipientOverride;
            Subject = subject;
            Body = body;
            Attachments = attachments;
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }
    }
}
