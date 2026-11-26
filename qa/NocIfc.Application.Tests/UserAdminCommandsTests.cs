using System.Security.Cryptography;
using System.Text;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class UserAdminCommandsTests
{
    [Fact]
    public async Task AdministratorCanCreateDisplayAccountWithHashedPassword()
    {
        var users = new StubUserAdminStore(null);
        var commands = new UserAdminCommands(users, new StubRoleDirectory([]), new StubPasswordHasher());

        var userId = await commands.CreateDisplayAccountAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []),
            "wall-screen",
            "wall-screen-password-123",
            "viewer",
            "  HQ Wall Screen  ",
            CancellationToken.None);

        Assert.Equal(10, userId);
        Assert.Equal("hash:wall-screen-password-123", users.DisplayAccount?.PasswordHash);
        Assert.Equal("HQ Wall Screen", users.DisplayAccount?.FullName);
    }

    [Fact]
    public async Task DelegatedManagerCannotCreateDisplayAccountWithElevatedRole()
    {
        var users = new StubUserAdminStore(null);
        var roles = new StubRoleDirectory(
        [new RoleDefinition(1, "recovery-reviewer", [], ["Action: Review Account Recovery Requests"], [])]);
        var commands = new UserAdminCommands(users, roles, new StubPasswordHasher());

        var error = await Assert.ThrowsAsync<UserAdminCommandException>(() => commands.CreateDisplayAccountAsync(
            Manager(), "wall-screen", "wall-screen-password-123", "recovery-reviewer", "", CancellationToken.None));

        Assert.Equal(403, error.StatusCode);
        Assert.Equal("Action: Manage Roles", error.Permission);
        Assert.Null(users.DisplayAccount);
    }

    [Fact]
    public async Task InvitationStoresOnlyHashedTokenAndNormalizesEmail()
    {
        var users = new StubUserAdminStore(null);
        var commands = new UserAdminCommands(users, new StubRoleDirectory([]), new StubPasswordHasher());

        var invitation = await commands.CreateInvitationAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []),
            " bob ",
            " Bob.Example@example.com ",
            " analyst ",
            "admin",
            72,
            CancellationToken.None);

        Assert.Equal("bob", invitation.Username);
        Assert.Equal("Bob.Example@example.com", invitation.Email);
        Assert.Equal("analyst", invitation.Role);
        Assert.Equal(43, invitation.Token.Length);
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(invitation.Token))).ToLowerInvariant(),
            users.Invitation?.TokenHash);
        Assert.Equal("bob.example@example.com", users.Invitation?.NormalizedEmail);
    }

    [Fact]
    public async Task DelegatedManagerCannotInviteElevatedRoles()
    {
        var users = new StubUserAdminStore(null);
        var roles = new StubRoleDirectory(
        [new RoleDefinition(1, "recovery-reviewer", [], ["Action: Review Account Recovery Requests"], [])]);
        var commands = new UserAdminCommands(users, roles, new StubPasswordHasher());

        var error = await Assert.ThrowsAsync<UserAdminCommandException>(() => commands.CreateInvitationAsync(
            Manager(), "person", "person@example.com", "recovery-reviewer", "manager", 72, CancellationToken.None));

        Assert.Equal(403, error.StatusCode);
        Assert.Equal("Action: Manage Roles", error.Permission);
        Assert.Null(users.Invitation);
    }

    [Fact]
    public async Task DelegatedManagersCannotMutateElevatedTargets()
    {
        var users = new StubUserAdminStore(new UserAdminTarget(8, "reviewer", "recovery-reviewer", "individual", null, false));
        var roles = new StubRoleDirectory(
        [
            new RoleDefinition(1, "recovery-reviewer", [], ["Action: Review Account Recovery Requests"], []),
            new RoleDefinition(2, "analyst", [], [], []),
        ]);
        var commands = new UserAdminCommands(users, roles, new StubPasswordHasher());

        var error = await Assert.ThrowsAsync<UserAdminCommandException>(() => commands.SetActiveAsync(
            Manager(), "reviewer", false, CancellationToken.None));

        Assert.Equal(403, error.StatusCode);
        Assert.Equal("role", error.Scope);
        Assert.Equal("Administrator", error.Permission);
        Assert.Equal(0, users.MutationCount);
    }

    [Fact]
    public async Task AdministratorRoleChangeDelegatesAtomicRevocationAndAuditToStore()
    {
        var target = new UserAdminTarget(8, "analyst", "viewer", "individual", null, false);
        var users = new StubUserAdminStore(target);
        var roles = new StubRoleDirectory(
        [
            new RoleDefinition(1, "administrator", [], [], []),
            new RoleDefinition(2, "viewer", [], [], []),
        ]);
        var commands = new UserAdminCommands(users, roles, new StubPasswordHasher());

        Assert.True(await commands.ChangeRoleAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []),
            "analyst",
            "viewer",
            CancellationToken.None));

        Assert.Equal((target, "viewer", 1), users.RoleChange);
    }

    [Fact]
    public async Task DelegatedManagerCanEditManageableProfileAndChangeAccountType()
    {
        var target = new UserAdminTarget(8, "wall-screen", "viewer", "individual", null, false);
        var users = new StubUserAdminStore(target);
        var commands = new UserAdminCommands(users, new StubRoleDirectory([]), new StubPasswordHasher());

        Assert.True(await commands.UpdateIdentityAsync(
            Manager(), "wall-screen", " HQ Screen ", " AV Operator ", " 555-0100 ", CancellationToken.None));
        Assert.Equal(("HQ Screen", "AV Operator", "555-0100", 2), users.IdentityChange);
        Assert.Equal("display", await commands.SetAccountTypeAsync(
            Manager(), "wall-screen", " DISPLAY ", CancellationToken.None));
        Assert.Equal((target, "display", 2), users.AccountTypeChange);
    }

    [Fact]
    public async Task DelegatedManagerCannotAssistedResetIndividualAccount()
    {
        var target = new UserAdminTarget(8, "alice", "analyst", "individual", "alice@example.com", true);
        var users = new StubUserAdminStore(target);
        var commands = new UserAdminCommands(users, new StubRoleDirectory([]), new StubPasswordHasher());

        var error = await Assert.ThrowsAsync<UserAdminCommandException>(() => commands.AdministratorResetAsync(
            Manager(), "alice", "new-password-123", CancellationToken.None));

        Assert.Equal(403, error.StatusCode);
        Assert.Equal("Action: Review Account Recovery Requests", error.Permission);
        Assert.Equal(0, users.MutationCount);
    }

    private static AuthenticatedUser Manager() =>
        new(2, "manager", "manager", ["Settings & Admin"], ["Action: Manage Users"], []);

    private sealed class StubRoleDirectory(IReadOnlyList<RoleDefinition> roles) : IRoleDirectory
    {
        public Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(roles);
    }

    private sealed class StubPasswordHasher : IPasswordHasher
    {
        public string Hash(string password) => $"hash:{password}";
    }

    private sealed class StubUserAdminStore(UserAdminTarget? target) : IUserAdminStore
    {
        public int MutationCount { get; private set; }
        public (UserAdminTarget Target, string Role, int ActorId)? RoleChange { get; private set; }
        public (string Username, string PasswordHash, string Role, string FullName)? DisplayAccount { get; private set; }
        public (string Username, string Email, string NormalizedEmail, string Role, string TokenHash, string CreatedBy, int TtlHours)? Invitation { get; private set; }
        public (string FullName, string JobTitle, string ContactInfo, int ActorId)? IdentityChange { get; private set; }
        public (UserAdminTarget Target, string AccountType, int ActorId)? AccountTypeChange { get; private set; }

        public Task<UserAdminTarget?> FindTargetAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult(target?.Username == username ? target : null);

        public Task<bool> ChangeRoleAsync(
            UserAdminTarget user,
            string role,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            RoleChange = (user, role, actorUserId);
            return Task.FromResult(true);
        }

        public Task<bool> SetActiveAsync(
            UserAdminTarget user,
            bool isActive,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            return Task.FromResult(true);
        }

        public Task<bool> RevokeSessionsAsync(
            UserAdminTarget user,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            return Task.FromResult(true);
        }

        public Task<bool> AdministratorResetAsync(
            UserAdminTarget user,
            string passwordHash,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            return Task.FromResult(true);
        }

        public Task<bool> UpdateIdentityAsync(
            UserAdminTarget user,
            string fullName,
            string jobTitle,
            string contactInfo,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            IdentityChange = (fullName, jobTitle, contactInfo, actorUserId);
            return Task.FromResult(true);
        }

        public Task<bool> SetAccountTypeAsync(
            UserAdminTarget user,
            string accountType,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken)
        {
            MutationCount++;
            AccountTypeChange = (user, accountType, actorUserId);
            return Task.FromResult(true);
        }

        public Task<DisplayAccountCreateResult> CreateDisplayAccountAsync(
            string username,
            string passwordHash,
            string role,
            string fullName,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken)
        {
            DisplayAccount = (username, passwordHash, role, fullName);
            return Task.FromResult(new DisplayAccountCreateResult(DisplayAccountCreateStatus.Created, 10));
        }

        public Task<RegistrationInviteCreateResult> CreateRegistrationInviteAsync(
            string username,
            string email,
            string normalizedEmail,
            string role,
            string tokenHash,
            string createdBy,
            int ttlHours,
            DateTime now,
            CancellationToken cancellationToken)
        {
            Invitation = (username, email, normalizedEmail, role, tokenHash, createdBy, ttlHours);
            return Task.FromResult(new RegistrationInviteCreateResult(
                RegistrationInviteCreateStatus.Created, 1, now.AddHours(ttlHours)));
        }

        public Task<IReadOnlyList<PendingRegistrationInvite>> GetPendingInvitationsAsync(
            DateTime now,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<PendingRegistrationInvite>>([]);

        public Task<bool> RevokeInvitationAsync(
            int inviteId,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<string?> GetPublicAppUrlAsync(CancellationToken cancellationToken) =>
            Task.FromResult<string?>("https://app.example.com");
    }
}
