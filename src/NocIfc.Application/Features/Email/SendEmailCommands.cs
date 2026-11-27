using System.IO;
using NocIfc.Application.Abstractions.Email;

namespace NocIfc.Application.Features.Email;

public sealed record SendEmailAttachmentInput(string FileName, string ContentType, string ContentBase64);

public sealed record SendEmailInput(
    string To,
    string Subject,
    string HtmlBody,
    IReadOnlyList<SendEmailAttachmentInput> Attachments);

public sealed class SendEmailCommands(IEmailSender emailSender)
{
    private const int MaxAttachmentBytes = 5 * 1024 * 1024;

    public async Task<EmailSendResult> SendAsync(SendEmailInput input, CancellationToken cancellationToken)
    {
        if (input.To.Length > 2000 || input.Subject.Length > 200 || input.HtmlBody.Length > 200_000
            || input.Attachments.Count > 5
            || input.Attachments.Any(attachment => attachment.FileName.Length > 120
                || attachment.ContentType.Length > 100 || attachment.ContentBase64.Length > 7_000_000))
        {
            throw new ArgumentException("Email fields exceed their maximum length.");
        }

        var attachments = new List<EmailAttachment>(input.Attachments.Count);
        foreach (var attachment in input.Attachments)
        {
            var fileName = Path.GetFileName(attachment.FileName);
            byte[] content;
            try
            {
                if (attachment.ContentBase64.Any(char.IsWhiteSpace))
                {
                    throw new FormatException();
                }
                content = Convert.FromBase64String(attachment.ContentBase64);
            }
            catch (FormatException)
            {
                return new EmailSendResult(false, $"Invalid email attachment: {fileName}");
            }
            if (content.Length > MaxAttachmentBytes)
            {
                return new EmailSendResult(false, $"Email attachment too large: {fileName}");
            }
            attachments.Add(new EmailAttachment(fileName, attachment.ContentType, content));
        }

        return await emailSender.SendHtmlWithAttachmentsAsync(
            input.To, input.Subject, input.HtmlBody, attachments, cancellationToken);
    }
}
