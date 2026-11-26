using System.Net;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class AccountRecoveryException(string message) : Exception(message);

public sealed record PasswordResetSubmissionResult(int? RequestId, IReadOnlyList<string> Notify);

public sealed record PasswordResetReviewResult(string Status, string Username, string? Email, string? Token);

public sealed class AccountRecoveryCommands(
    IAccountRecoveryStore recovery,
    RecoveryReviewerQueries reviewers,
    IPasswordHasher passwordHasher)
{
    private const string ReviewAction = "Action: Review Account Recovery Requests";

    public async Task<PasswordResetSubmissionResult> SubmitPasswordResetRequestAsync(
        string? identifier,
        string? sourceIp,
        CancellationToken cancellationToken)
    {
        var submitted = (identifier ?? "").Trim();
        var normalized = submitted.ToLowerInvariant();
        var safeIp = IPAddress.TryParse(sourceIp, out var address) ? address.ToString() : null;
        var result = await recovery.SubmitPasswordResetRequestAsync(
            normalized,
            CapabilityTokenHash.Sha256(normalized),
            safeIp,
            DateTime.UtcNow,
            cancellationToken);
        if (result.RateLimited || result.RequestId is null || result.UserId is null)
        {
            return new PasswordResetSubmissionResult(null, []);
        }

        var reviewerEmails = await reviewers.GetEmailAddressesAsync(ReviewAction, result.UserId, cancellationToken);
        return new PasswordResetSubmissionResult(result.RequestId, reviewerEmails);
    }

    public Task<IReadOnlyList<PasswordResetRequestInfo>> ListPasswordResetRequestsAsync(CancellationToken cancellationToken) =>
        recovery.ListPasswordResetRequestsAsync(cancellationToken);

    public async Task<PasswordResetReviewResult> ReviewPasswordResetRequestAsync(
        int requestId,
        int reviewerId,
        bool approve,
        string? reason,
        CancellationToken cancellationToken)
    {
        var decisionReason = (reason ?? "").Trim();
        if (decisionReason.Length > 1000)
        {
            decisionReason = decisionReason[..1000];
        }
        var token = approve ? CapabilityTokenHash.CreateToken() : null;
        var result = await recovery.ReviewPasswordResetRequestAsync(
            requestId,
            reviewerId,
            approve,
            decisionReason,
            token is null ? null : CapabilityTokenHash.Sha256(token),
            DateTime.UtcNow,
            cancellationToken);
        return new PasswordResetReviewResult(result.Status, result.Username, result.Email, token);
    }

    public async Task<bool> CompletePasswordResetAsync(
        string? rawToken,
        string? newPassword,
        CancellationToken cancellationToken)
    {
        if ((newPassword?.EnumerateRunes().Count() ?? 0) < 12)
        {
            throw new ArgumentException("Password must be at least 12 characters.");
        }

        var tokenHash = CapabilityTokenHash.Sha256(rawToken ?? "");
        var now = DateTime.UtcNow;
        if (!await recovery.HasValidPasswordResetTokenAsync(tokenHash, now, cancellationToken))
        {
            return false;
        }

        var passwordHash = passwordHasher.Hash(newPassword!);
        return await recovery.CompletePasswordResetAsync(tokenHash, passwordHash, now, cancellationToken);
    }
}
