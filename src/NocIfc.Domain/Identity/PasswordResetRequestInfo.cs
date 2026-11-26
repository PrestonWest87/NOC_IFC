namespace NocIfc.Domain.Identity;

public sealed record PasswordResetRequestInfo(
    int Id,
    int UserId,
    string Username,
    string? FullName,
    string? Email,
    bool EmailVerified,
    string AccountType,
    DateTime? RequestedAt);

public sealed record PasswordResetSubmission(bool RateLimited, int? RequestId, int? UserId);

public sealed record PasswordResetDecisionResult(string Status, string Username, string? Email);
