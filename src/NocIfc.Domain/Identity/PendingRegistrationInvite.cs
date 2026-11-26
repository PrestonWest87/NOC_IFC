namespace NocIfc.Domain.Identity;

public sealed record PendingRegistrationInvite(
    int Id,
    string Username,
    string Email,
    string Role,
    DateTime? CreatedAt,
    DateTime ExpiresAt,
    string CreatedBy,
    DateTime? RevokedAt);
