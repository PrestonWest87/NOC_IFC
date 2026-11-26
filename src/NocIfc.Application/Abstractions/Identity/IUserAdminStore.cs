using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public enum DisplayAccountCreateStatus
{
    Created,
    UsernameTaken,
    RoleNotFound,
}

public sealed record DisplayAccountCreateResult(DisplayAccountCreateStatus Status, int? UserId = null);

public enum RegistrationInviteCreateStatus
{
    Created,
    UsernameExists,
    EmailInUse,
    EmailPendingRecovery,
    RoleNotFound,
    EmailHasPendingInvite,
}

public sealed record RegistrationInviteCreateResult(
    RegistrationInviteCreateStatus Status,
    int? InviteId = null,
    DateTime? ExpiresAt = null);

public interface IUserAdminStore
{
    Task<UserAdminTarget?> FindTargetAsync(string username, CancellationToken cancellationToken);
    Task<bool> ChangeRoleAsync(UserAdminTarget target, string role, int actorUserId, CancellationToken cancellationToken);
    Task<bool> SetActiveAsync(UserAdminTarget target, bool isActive, int actorUserId, CancellationToken cancellationToken);
    Task<bool> RevokeSessionsAsync(UserAdminTarget target, int actorUserId, CancellationToken cancellationToken);
    Task<bool> AdministratorResetAsync(
        UserAdminTarget target,
        string passwordHash,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken);
    Task<bool> UpdateIdentityAsync(
        UserAdminTarget target,
        string fullName,
        string jobTitle,
        string contactInfo,
        int actorUserId,
        CancellationToken cancellationToken);
    Task<bool> SetAccountTypeAsync(
        UserAdminTarget target,
        string accountType,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken);
    Task<DisplayAccountCreateResult> CreateDisplayAccountAsync(
        string username,
        string passwordHash,
        string role,
        string fullName,
        int actorUserId,
        DateTime now,
        CancellationToken cancellationToken);
    Task<RegistrationInviteCreateResult> CreateRegistrationInviteAsync(
        string username,
        string email,
        string normalizedEmail,
        string role,
        string tokenHash,
        string createdBy,
        int ttlHours,
        DateTime now,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<PendingRegistrationInvite>> GetPendingInvitationsAsync(
        DateTime now,
        CancellationToken cancellationToken);
    Task<bool> RevokeInvitationAsync(int inviteId, int actorUserId, DateTime now, CancellationToken cancellationToken);
    Task<string?> GetPublicAppUrlAsync(CancellationToken cancellationToken);
}
