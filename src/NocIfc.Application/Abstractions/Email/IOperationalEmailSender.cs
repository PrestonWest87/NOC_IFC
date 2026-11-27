namespace NocIfc.Application.Abstractions.Email;

public sealed record OperationalEmailEnvelope(
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string Subject,
    string TextBody,
    string HtmlBody,
    IReadOnlyList<EmailAttachment> Attachments);

public interface IOperationalEmailSender
{
    Task<EmailSendResult> SendOperationalEmailAsync(
        OperationalEmailEnvelope envelope,
        CancellationToken cancellationToken);
}
