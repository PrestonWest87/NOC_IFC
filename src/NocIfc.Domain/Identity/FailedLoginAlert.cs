namespace NocIfc.Domain.Identity;

public sealed record FailedLoginAttemptEntry(string Username, string? SourceIp, DateTime AttemptedAt);

public sealed record FailedLoginAlert(
    string Recipients,
    int Threshold,
    int WindowMinutes,
    DateTime TriggeredAt,
    IReadOnlyList<FailedLoginAttemptEntry> Attempts);
