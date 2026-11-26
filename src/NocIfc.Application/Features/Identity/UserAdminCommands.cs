using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
using System.Text.RegularExpressions;

namespace NocIfc.Application.Features.Identity;

public sealed class UserAdminCommandException(
    string message,
    int statusCode = 400,
    string? scope = null,
    string? permission = null) : Exception(message)
{
    public int StatusCode { get; } = statusCode;
    public string? Scope { get; } = scope;
    public string? Permission { get; } = permission;
}

public sealed class UserAdminCommands(IUserAdminStore users, IRoleDirectory roles, IPasswordHasher passwordHasher)
{
    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$", RegexOptions.CultureInvariant);

    public sealed record CreatedInvitation(string Username, string Email, string Role, string Token, DateTime ExpiresAt);

    public async Task<IReadOnlyList<PendingRegistrationInvite>> ListPendingInvitationsAsync(
        CancellationToken cancellationToken) =>
        await users.GetPendingInvitationsAsync(DateTime.UtcNow, cancellationToken);

    public async Task<CreatedInvitation> CreateInvitationAsync(
        AuthenticatedUser actor,
        string? username,
        string? email,
        string? role,
        string createdBy,
        int ttlHours,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (username is null || username.Length is < 3 or > 64
            || email is null || email.Length is < 3 or > 254
            || role is null || role.Length is < 1 or > 64
            || ttlHours is < 1 or > 336)
        {
            throw new UserAdminCommandException("Invitation fields are invalid.");
        }

        var normalizedUsername = username.Trim();
        var normalizedRole = role.Trim();
        if (!actor.IsAdministrator)
        {
            var roleDefinition = (await roles.GetAllAsync(cancellationToken)).FirstOrDefault(item =>
                string.Equals(item.Name, normalizedRole, StringComparison.Ordinal));
            EnsureAssignableRole(actor, normalizedRole, roleDefinition);
        }

        string displayEmail;
        string normalizedEmail;
        try
        {
            (displayEmail, normalizedEmail) = EmailAddressRules.NormalizeUserEmail(email);
        }
        catch (ArgumentException exception)
        {
            throw new UserAdminCommandException(exception.Message);
        }
        if (!UsernamePattern.IsMatch(normalizedUsername))
        {
            throw new UserAdminCommandException("Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'.");
        }
        if (normalizedRole.Length == 0)
        {
            throw new UserAdminCommandException("A valid role is required.");
        }

        var now = DateTime.UtcNow;
        var expiresAt = now.AddHours(Math.Clamp(ttlHours, 1, 336));
        var token = CapabilityTokenHash.CreateToken();
        var result = await users.CreateRegistrationInviteAsync(
            normalizedUsername,
            displayEmail,
            normalizedEmail,
            normalizedRole,
            CapabilityTokenHash.Sha256(token),
            createdBy,
            ttlHours,
            now,
            cancellationToken);

        return result.Status switch
        {
            RegistrationInviteCreateStatus.Created =>
                new CreatedInvitation(normalizedUsername, displayEmail, normalizedRole, token, result.ExpiresAt!.Value),
            RegistrationInviteCreateStatus.UsernameExists =>
                throw new UserAdminCommandException("That username is already registered."),
            RegistrationInviteCreateStatus.EmailInUse =>
                throw new UserAdminCommandException("That email address is already associated with an account."),
            RegistrationInviteCreateStatus.EmailPendingRecovery =>
                throw new UserAdminCommandException("That email address is pending recovery-email approval for another account."),
            RegistrationInviteCreateStatus.EmailHasPendingInvite =>
                throw new UserAdminCommandException("That email address already has a pending invitation."),
            _ => throw new UserAdminCommandException("That role does not exist."),
        };
    }

    public async Task<CreatedInvitation> ResendInvitationAsync(
        AuthenticatedUser actor,
        int inviteId,
        CancellationToken cancellationToken)
    {
        var invite = (await users.GetPendingInvitationsAsync(DateTime.UtcNow, cancellationToken))
            .FirstOrDefault(item => item.Id == inviteId);
        if (invite is null)
        {
            throw new UserAdminCommandException("Pending invitation not found.", 404);
        }
        return await CreateInvitationAsync(
            actor,
            invite.Username,
            invite.Email,
            invite.Role,
            actor.Username,
            72,
            cancellationToken);
    }

    public Task<string?> GetPublicAppUrlAsync(CancellationToken cancellationToken) =>
        users.GetPublicAppUrlAsync(cancellationToken);

    public Task<bool> RevokeInvitationAsync(int inviteId, int actorUserId, CancellationToken cancellationToken) =>
        users.RevokeInvitationAsync(inviteId, actorUserId, DateTime.UtcNow, cancellationToken);

    public async Task<int> CreateDisplayAccountAsync(
        AuthenticatedUser actor,
        string? username,
        string? password,
        string? role,
        string? fullName,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (string.IsNullOrEmpty(username) || username.Length is < 3 or > 64)
        {
            throw new UserAdminCommandException("Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'.");
        }
        if (string.IsNullOrEmpty(password) || password.Length is < 12 or > 256)
        {
            throw new UserAdminCommandException("Password must be between 12 and 256 characters.");
        }
        if (string.IsNullOrEmpty(role) || role.Length > 64)
        {
            throw new UserAdminCommandException("A valid role is required.");
        }
        if ((fullName?.Length ?? 0) > 200)
        {
            throw new UserAdminCommandException("full_name must be no longer than 200 characters.");
        }

        var normalizedUsername = username.Trim();
        var normalizedRole = role.Trim();
        if (!UsernamePattern.IsMatch(normalizedUsername))
        {
            throw new UserAdminCommandException("Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'.");
        }

        RoleDefinition? assignableRole = null;
        if (!actor.IsAdministrator)
        {
            assignableRole = (await roles.GetAllAsync(cancellationToken)).FirstOrDefault(item =>
                string.Equals(item.Name, normalizedRole, StringComparison.Ordinal));
            EnsureAssignableRole(actor, normalizedRole, assignableRole);
        }

        var created = await users.CreateDisplayAccountAsync(
            normalizedUsername,
            passwordHasher.Hash(password),
            normalizedRole,
            (fullName ?? "").Trim(),
            actor.Id,
            DateTime.UtcNow,
            cancellationToken);
        return created.Status switch
        {
            DisplayAccountCreateStatus.Created => created.UserId!.Value,
            DisplayAccountCreateStatus.UsernameTaken => throw new UserAdminCommandException("That username is already registered."),
            _ => throw new UserAdminCommandException("That role does not exist."),
        };
    }

    public async Task<bool> ChangeRoleAsync(
        AuthenticatedUser actor,
        string username,
        string newRole,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var roleDefinitions = await roles.GetAllAsync(cancellationToken);
        var requestedRole = roleDefinitions.FirstOrDefault(role =>
            string.Equals(role.Name, newRole, StringComparison.Ordinal));
        EnsureAssignableRole(actor, newRole, requestedRole);

        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return false;
        }
        EnsureManageableTarget(actor, target, roleDefinitions);
        if (requestedRole is null)
        {
            throw new UserAdminCommandException("That role does not exist.");
        }

        return await users.ChangeRoleAsync(target, newRole, actor.Id, cancellationToken);
    }

    public async Task<bool> SetActiveAsync(
        AuthenticatedUser actor,
        string username,
        bool isActive,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return false;
        }
        EnsureManageableTarget(actor, target, await roles.GetAllAsync(cancellationToken));
        return await users.SetActiveAsync(target, isActive, actor.Id, cancellationToken);
    }

    public async Task<bool> RevokeSessionsAsync(
        AuthenticatedUser actor,
        string username,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return false;
        }
        EnsureManageableTarget(actor, target, await roles.GetAllAsync(cancellationToken));
        return await users.RevokeSessionsAsync(target, actor.Id, cancellationToken);
    }

    public async Task<bool> AdministratorResetAsync(
        AuthenticatedUser actor,
        string username,
        string? newPassword,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (newPassword is null || newPassword.Length is < 12 or > 256)
        {
            throw new UserAdminCommandException("Password must be between 12 and 256 characters.");
        }

        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return false;
        }
        if (target.AccountType != "display" && !actor.IsAdministrator)
        {
            throw new UserAdminCommandException(
                "Individual accounts must use administrator-reviewed recovery unless a root administrator performs an assisted reset.",
                403,
                "action",
                "Action: Review Account Recovery Requests");
        }
        if (target.Email is not null && target.EmailVerified && target.AccountType != "display" && !actor.IsAdministrator)
        {
            throw new UserAdminCommandException(
                "Accounts with an approved recovery email must use the reviewed password-reset flow.",
                409);
        }

        EnsureManageableTarget(actor, target, await roles.GetAllAsync(cancellationToken));
        return await users.AdministratorResetAsync(
            target,
            passwordHasher.Hash(newPassword),
            actor.Id,
            DateTime.UtcNow,
            cancellationToken);
    }

    public async Task<bool> UpdateIdentityAsync(
        AuthenticatedUser actor,
        string username,
        string? fullName,
        string? jobTitle,
        string? contactInfo,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if ((fullName?.Length ?? 0) > 200 || (jobTitle?.Length ?? 0) > 200 || (contactInfo?.Length ?? 0) > 500)
        {
            throw new UserAdminCommandException("Profile fields exceed their maximum length.");
        }
        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return false;
        }
        EnsureManageableTarget(actor, target, await roles.GetAllAsync(cancellationToken));
        return await users.UpdateIdentityAsync(
            target,
            (fullName ?? "").Trim(),
            (jobTitle ?? "").Trim(),
            (contactInfo ?? "").Trim(),
            actor.Id,
            cancellationToken);
    }

    public async Task<string?> SetAccountTypeAsync(
        AuthenticatedUser actor,
        string username,
        string? requestedType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var accountType = (requestedType ?? "").Trim().ToLowerInvariant();
        if (accountType is not ("individual" or "display"))
        {
            throw new UserAdminCommandException("Account type must be 'individual' or 'display'.");
        }
        var target = await users.FindTargetAsync(username, cancellationToken);
        if (target is null)
        {
            return null;
        }
        EnsureManageableTarget(actor, target, await roles.GetAllAsync(cancellationToken));
        var updated = await users.SetAccountTypeAsync(
            target,
            accountType,
            actor.Id,
            DateTime.UtcNow,
            cancellationToken);
        return updated ? accountType : null;
    }

    private static void EnsureAssignableRole(
        AuthenticatedUser actor,
        string roleName,
        RoleDefinition? requestedRole)
    {
        if (actor.IsAdministrator)
        {
            return;
        }
        if (RoleAccessPolicy.IsAdministratorRole(roleName))
        {
            throw new UserAdminCommandException(
                "Only an administrator can assign the administrator role.",
                403,
                "role",
                "Administrator");
        }
        if (RoleAccessPolicy.IsElevatedRole(requestedRole))
        {
            throw new UserAdminCommandException(
                "Only an administrator can assign a user-management or recovery-review role.",
                403,
                "action",
                "Action: Manage Roles");
        }
    }

    private static void EnsureManageableTarget(
        AuthenticatedUser actor,
        UserAdminTarget target,
        IReadOnlyList<RoleDefinition> roleDefinitions)
    {
        if (actor.IsAdministrator)
        {
            return;
        }
        var targetRole = roleDefinitions.FirstOrDefault(role =>
            string.Equals(role.Name, target.Role, StringComparison.Ordinal));
        if (RoleAccessPolicy.IsAdministratorRole(target.Role) || RoleAccessPolicy.IsElevatedRole(targetRole))
        {
            throw new UserAdminCommandException(
                "Only an administrator can manage an administrator or user-administrator account.",
                403,
                "role",
                "Administrator");
        }
    }

}
