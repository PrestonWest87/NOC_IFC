using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IRecoveryEmailStore
{
    Task<int> SubmitAsync(int userId, string email, string normalizedEmail, DateTime now, CancellationToken cancellationToken);
    Task<IReadOnlyList<RecoveryEmailRequestInfo>> ListPendingAsync(CancellationToken cancellationToken);
    Task<RecoveryEmailDecisionResult> ReviewAsync(
        int requestId,
        int reviewerId,
        bool approve,
        string reason,
        string? tokenHash,
        DateTime now,
        CancellationToken cancellationToken);
    Task<bool> VerifyAsync(string tokenHash, DateTime now, CancellationToken cancellationToken);
    Task<RecoveryEmailVerification> ResendAsync(
        int userId,
        string tokenHash,
        DateTime now,
        DateTime expiresAt,
        CancellationToken cancellationToken);
}
