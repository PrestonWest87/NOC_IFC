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
