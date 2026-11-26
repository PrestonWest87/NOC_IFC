namespace NocIfc.Domain.Identity;

public sealed record UserAdminTarget(
    int Id,
    string Username,
    string? Role,
    string AccountType,
    string? Email,
    bool EmailVerified);
