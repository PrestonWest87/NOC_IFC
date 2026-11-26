namespace NocIfc.Domain.Identity;

public sealed record UserDirectoryEntry(
    int Id,
    string Username,
    string? FullName,
    string? JobTitle,
    string? ContactInfo,
    string? Email,
    bool EmailVerified,
    string EmailStatus,
    string? PendingEmail,
    string AccountType,
    string? Role,
    bool IsActive,
    DateTime? CreatedAt,
    DateTime? LastLoginAt,
    DateTime? LastActivityAt,
    bool InvitationPending);
