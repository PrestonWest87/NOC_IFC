using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class RecoveryEmailException(string message) : Exception(message);

public sealed record RecoveryEmailSubmission(int RequestId, IReadOnlyList<string> Notify);

public sealed record RecoveryEmailDecision(string Status, string Username, string? Email, string? Token);

public sealed record RecoveryEmailVerificationLink(string Username, string Email, string Token);

public sealed class RecoveryEmailCommands(IRecoveryEmailStore requests, RecoveryReviewerQueries reviewers)
{
    private const string ApprovalAction = "Action: Approve Recovery Email Changes";

    public async Task<RecoveryEmailSubmission> SubmitAsync(
        int userId,
        string? email,
        CancellationToken cancellationToken)
    {
        (string displayEmail, string normalizedEmail) normalized;
        try
        {
            normalized = EmailAddressRules.NormalizeUserEmail(email);
        }
        catch (ArgumentException exception)
        {
            throw new RecoveryEmailException(exception.Message);
        }

        var requestId = await requests.SubmitAsync(
            userId,
            normalized.displayEmail,
            normalized.normalizedEmail,
            DateTime.UtcNow,
            cancellationToken);
        var notify = await reviewers.GetEmailAddressesAsync(ApprovalAction, userId, cancellationToken);
        return new RecoveryEmailSubmission(requestId, notify);
    }

    public Task<IReadOnlyList<RecoveryEmailRequestInfo>> ListPendingAsync(CancellationToken cancellationToken) =>
        requests.ListPendingAsync(cancellationToken);

    public async Task<RecoveryEmailDecision> ReviewAsync(
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
        var result = await requests.ReviewAsync(
            requestId,
            reviewerId,
            approve,
            decisionReason,
            token is null ? null : CapabilityTokenHash.Sha256(token),
            DateTime.UtcNow,
            cancellationToken);
        return new RecoveryEmailDecision(result.Status, result.Username, result.Email, token);
    }

    public Task<bool> VerifyAsync(string? token, CancellationToken cancellationToken) =>
        string.IsNullOrEmpty(token)
            ? Task.FromResult(false)
            : requests.VerifyAsync(CapabilityTokenHash.Sha256(token), DateTime.UtcNow, cancellationToken);

    public async Task<RecoveryEmailVerificationLink> ResendAsync(int userId, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        var token = CapabilityTokenHash.CreateToken();
        var result = await requests.ResendAsync(
            userId,
            CapabilityTokenHash.Sha256(token),
            now,
            now.AddHours(24),
            cancellationToken);
        return new RecoveryEmailVerificationLink(result.Username, result.Email, token);
    }
}
