namespace NocIfc.Domain.Identity;

public sealed record LoginUser(
    int Id,
    string Username,
    string? Role,
    string? FullName,
    string? JobTitle,
    string? ContactInfo,
    string? DefaultShift,
    string? Theme,
    string AccountType,
    string? Email,
    string? EmailNormalized,
    DateTime? EmailVerifiedAt,
    bool IsActive,
    DateTime? CreatedAt,
    DateTime? LastLoginAt,
    DateTime? LastActivityAt,
    string RecoveryEmailStatus,
    string? PendingEmail,
    IReadOnlyList<string> AllowedPages,
    IReadOnlyList<string> AllowedActions,
    IReadOnlyList<string> AllowedSiteTypes);
