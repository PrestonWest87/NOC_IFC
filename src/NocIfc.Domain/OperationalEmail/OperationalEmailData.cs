namespace NocIfc.Domain.OperationalEmail;

public sealed record OperationalEmailTemplateDefault(
    string TemplateKey,
    string Label,
    string Description,
    string DefaultSubject,
    string DefaultBody,
    string DefaultTo,
    string DefaultCc,
    string DefaultBcc,
    DateTime? UpdatedAt);

public sealed record OperationalEmailSignatureEntry(
    int Id,
    string Name,
    string Content,
    bool IsActive,
    bool IsDefault,
    int? CreatedByUserId,
    int? UpdatedByUserId,
    DateTime? CreatedAt,
    DateTime? UpdatedAt);

public sealed record OperationalEmailSignatureValues(
    string Name,
    string Content,
    bool IsActive,
    bool IsDefault);

public sealed record OperationalEmailSignatureMutation(
    bool Found,
    bool NameConflict,
    OperationalEmailSignatureEntry? Signature);

public sealed record OperationalEmailAttachmentSnapshot(string FileName, string ContentType, byte[] Content);

public sealed record OperationalEmailMessageSnapshot(
    string TemplateKey,
    int CreatedByUserId,
    int? SignatureId,
    string? SignatureName,
    string? SignatureContent,
    int? ParentEmailId,
    string? GroupId,
    string? GroupCompany,
    bool BccCopyOnly,
    string Subject,
    string Body,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string ScheduleType,
    string Timezone,
    DateTime? ScheduledAt,
    string? RecurrenceTime,
    int? RecurrenceWeekday,
    DateTime? NextRunAt,
    IReadOnlyList<OperationalEmailAttachmentSnapshot> Attachments);

public sealed record OperationalEmailQueuedMessage(
    int Id,
    string TemplateKey,
    string? GroupId,
    string? GroupCompany,
    bool BccCopyOnly,
    int? ParentEmailId,
    int? SignatureId,
    string? SignatureName,
    string? SignatureContent,
    string Subject,
    string Body,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string ScheduleType,
    string? RecurrenceTime,
    int? RecurrenceWeekday,
    IReadOnlyList<OperationalEmailAttachmentSnapshot> Attachments);

public sealed record OperationalEmailSourceMessage(
    int Id,
    string TemplateKey,
    string? GroupId,
    string? GroupCompany,
    bool BccCopyOnly,
    string Subject,
    string Body,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    int? SignatureId,
    string? SignatureName,
    string? SignatureContent);

public sealed record OperationalEmailAttachmentMetadata(string FileName, string ContentType, int SizeBytes);

public sealed record OperationalEmailScheduledEntry(
    int Id,
    string TemplateKey,
    int? CreatedByUserId,
    int? SignatureId,
    string? SignatureName,
    int? ParentEmailId,
    string? GroupId,
    string? GroupCompany,
    bool BccCopyOnly,
    string Subject,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string ScheduleType,
    string Timezone,
    DateTime? ScheduledAt,
    string? RecurrenceTime,
    int? RecurrenceWeekday,
    DateTime? NextRunAt,
    string Status,
    DateTime? LastSentAt,
    string? LastError,
    DateTime? CreatedAt,
    IReadOnlyList<OperationalEmailAttachmentMetadata> Attachments);

public sealed record OperationalEmailDeliveryHistoryEntry(
    int Id,
    int EmailId,
    string TemplateKey,
    bool BccCopyOnly,
    string Status,
    string SmtpProvider,
    string? SenderAddress,
    string? SignatureName,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string Subject,
    IReadOnlyList<string> AttachmentNames,
    DateTime? AttemptedAt,
    DateTime? SentAt,
    string? ErrorMessage);

public sealed record OperationalEmailDeliveryDetail(
    int Id,
    int EmailId,
    string? GroupId,
    string? GroupCompany,
    bool BccCopyOnly,
    string TemplateKey,
    string Status,
    string SmtpProvider,
    string? SenderAddress,
    string? SignatureName,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    string Subject,
    string Body,
    IReadOnlyDictionary<string, string> Fields,
    IReadOnlyList<string> AttachmentNames,
    DateTime? AttemptedAt,
    DateTime? SentAt,
    string? ErrorMessage);

public sealed record OperationalEmailSourceGroup(
    int Id,
    string? GroupId,
    bool Grouped,
    int CompanyCount,
    IReadOnlyList<string> Companies,
    IReadOnlyList<int> EmailIds,
    string TemplateKey,
    string Subject,
    IReadOnlyList<string> ToRecipients,
    IReadOnlyList<string> CcRecipients,
    IReadOnlyList<string> BccRecipients,
    IReadOnlyDictionary<string, string> Fields,
    DateTime? SentAt);

public enum OperationalEmailCancellationResult
{
    Cancelled,
    NotFound,
    InProgress,
    NotScheduled,
}
