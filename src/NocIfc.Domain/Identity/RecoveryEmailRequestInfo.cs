namespace NocIfc.Domain.Identity;

public sealed record RecoveryEmailRequestInfo(
    int Id,
    int UserId,
    string Username,
    string? FullName,
    string AccountType,
    string? CurrentEmail,
    string RequestedEmail,
    DateTime? RequestedAt);

public sealed record RecoveryEmailDecisionResult(string Status, string Username, string? Email);

public sealed record RecoveryEmailVerification(string Username, string Email);
