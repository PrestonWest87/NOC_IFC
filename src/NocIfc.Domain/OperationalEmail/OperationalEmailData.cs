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
