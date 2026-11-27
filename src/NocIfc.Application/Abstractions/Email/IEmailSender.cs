namespace NocIfc.Application.Abstractions.Email;

public sealed record EmailSendResult(bool Success, string Message);

public interface IEmailSender
{
    Task<EmailSendResult> SendPlainTextAsync(
        string recipientOverride,
        string subject,
        string body,
        CancellationToken cancellationToken);
    Task<EmailSendResult> SendHtmlAsync(
        string recipientOverride,
        string subject,
        string body,
        CancellationToken cancellationToken);
}
