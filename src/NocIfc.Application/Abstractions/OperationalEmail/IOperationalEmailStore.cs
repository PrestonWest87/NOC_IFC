using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Application.Abstractions.OperationalEmail;

public interface IOperationalEmailStore
{
    Task EnsureTemplateDefaultsAsync(IReadOnlyList<OperationalEmailTemplateDefault> defaults, CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailTemplateDefault>> GetTemplateDefaultsAsync(CancellationToken cancellationToken);
    Task<bool> UpdateTemplateDefaultsAsync(
        string templateKey,
        IReadOnlyDictionary<string, string> values,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailSignatureEntry>> GetSignaturesAsync(bool includeInactive, CancellationToken cancellationToken);
    Task<OperationalEmailSignatureEntry?> GetSignatureAsync(int signatureId, CancellationToken cancellationToken);
    Task<OperationalEmailSignatureMutation> CreateSignatureAsync(
        OperationalEmailSignatureValues signature,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<OperationalEmailSignatureMutation> UpdateSignatureAsync(
        int signatureId,
        OperationalEmailSignatureValues signature,
        IReadOnlyList<string> changedFields,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<int> CreateEmailAsync(OperationalEmailMessageSnapshot email, CancellationToken cancellationToken);
    Task<int> CreateDeliverySnapshotAsync(
        int emailId,
        string smtpProvider,
        string? senderAddress,
        DateTime attemptedAtUtc,
        CancellationToken cancellationToken);
    Task CompleteDeliveryAsync(
        int emailId,
        int deliveryId,
        bool success,
        string message,
        DateTime completedAtUtc,
        DateTime? nextRunAtUtc,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<int>> ClaimDueEmailsAsync(
        DateTime nowUtc,
        TimeSpan staleAfter,
        int limit,
        CancellationToken cancellationToken);
    Task<OperationalEmailQueuedMessage?> GetProcessingEmailAsync(
        int emailId,
        CancellationToken cancellationToken);
    Task UpdateProcessingEmailContentAsync(
        int emailId,
        string body,
        IReadOnlyDictionary<string, string> fields,
        DateTime updatedAtUtc,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailSourceMessage>> GetSuccessfulSourceMessagesAsync(
        int sourceEmailId,
        IReadOnlyList<string> allowedTemplateKeys,
        bool includeBccCopies,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailScheduledEntry>> GetScheduledEmailsAsync(
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailScheduledEntry>> GetScheduledEmailsByIdsAsync(
        IReadOnlyList<int> emailIds,
        CancellationToken cancellationToken);
    Task<OperationalEmailCancellationResult> CancelScheduledEmailAsync(
        int emailId,
        int actorUserId,
        DateTime cancelledAtUtc,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailDeliveryHistoryEntry>> GetDeliveryHistoryAsync(
        int limit,
        CancellationToken cancellationToken);
    Task<OperationalEmailDeliveryDetail?> GetDeliveryDetailAsync(
        int deliveryId,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<OperationalEmailSourceGroup>> GetSentSourceGroupsAsync(
        IReadOnlyList<string> templateKeys,
        int limit,
        CancellationToken cancellationToken);
}
