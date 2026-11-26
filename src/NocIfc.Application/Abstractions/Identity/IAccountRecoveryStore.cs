using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IAccountRecoveryStore
{
    Task<PasswordResetSubmission> SubmitPasswordResetRequestAsync(
        string normalizedIdentifier,
        string identifierHash,
        string? requesterIp,
        DateTime now,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<PasswordResetRequestInfo>> ListPasswordResetRequestsAsync(CancellationToken cancellationToken);
    Task<PasswordResetDecisionResult> ReviewPasswordResetRequestAsync(
        int requestId,
        int reviewerId,
        bool approve,
        string reason,
        string? tokenHash,
        DateTime now,
        CancellationToken cancellationToken);
    Task<bool> HasValidPasswordResetTokenAsync(string tokenHash, DateTime now, CancellationToken cancellationToken);
    Task<bool> CompletePasswordResetAsync(
        string tokenHash,
        string passwordHash,
        DateTime now,
        CancellationToken cancellationToken);
}
