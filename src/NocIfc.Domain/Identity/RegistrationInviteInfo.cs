namespace NocIfc.Domain.Identity;

public sealed record RegistrationInviteInfo(
    string Username,
    string Role,
    string Email,
    DateTime ExpiresAt);
