using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AccountRecoveryCommandsTests
{
    [Fact]
    public async Task ResetRequestNotifiesOnlyOtherActiveVerifiedReviewers()
    {
        var users = new StubUserDirectory(
        [
            User(2, "alice", "alice@example.com", true, true, "analyst"),
            User(1, "admin", "admin@example.com", true, true, "admin"),
            User(3, "reviewer", "reviewer@example.com", true, true, "reviewer"),
            User(4, "disabled", "disabled@example.com", false, true, "admin"),
            User(5, "unverified", "unverified@example.com", true, false, "reviewer"),
            User(6, "analyst", "analyst@example.com", true, true, "analyst"),
        ]);
        var roles = new StubRoleDirectory(
        [
            new RoleDefinition(1, "admin", [], [], []),
            new RoleDefinition(2, "reviewer", ["Settings & Admin"],
                ["Action: Review Account Recovery Requests", "Tab: Settings -> Users & Roles"], []),
            new RoleDefinition(3, "analyst", ["Global Dashboards"], [], []),
        ]);
        var store = new StubRecoveryStore(new PasswordResetSubmission(false, 7, 2));
        var commands = new AccountRecoveryCommands(store, new RecoveryReviewerQueries(users, roles), new StubPasswordHasher());

        var result = await commands.SubmitPasswordResetRequestAsync(" Alice ", "192.0.2.5", CancellationToken.None);

        Assert.Equal(7, result.RequestId!.Value);
        Assert.Equal(new[] { "admin@example.com", "reviewer@example.com" }, result.Notify);
        Assert.Equal("alice", store.Identifier);
        Assert.Equal("192.0.2.5", store.RequesterIp);
        Assert.Equal(CapabilityTokenHash.Sha256("alice"), store.IdentifierHash);
    }

    private static UserDirectoryEntry User(
        int id,
        string username,
        string email,
        bool active,
        bool emailVerified,
        string role) =>
        new(id, username, null, null, null, email, emailVerified, "verified", null, "individual", role,
            active, null, null, null, false);

    private sealed class StubUserDirectory(IReadOnlyList<UserDirectoryEntry> rows) : IUserDirectory
    {
        public Task<IReadOnlyList<UserDirectoryEntry>> GetAllAsync(CancellationToken cancellationToken) => Task.FromResult(rows);
    }

    private sealed class StubRoleDirectory(IReadOnlyList<RoleDefinition> rows) : IRoleDirectory
    {
        public Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken) => Task.FromResult(rows);
    }

    private sealed class StubPasswordHasher : IPasswordHasher
    {
        public string Hash(string password) => password;
    }

    private sealed class StubRecoveryStore(PasswordResetSubmission submission) : IAccountRecoveryStore
    {
        public string? Identifier { get; private set; }
        public string? IdentifierHash { get; private set; }
        public string? RequesterIp { get; private set; }

        public Task<PasswordResetSubmission> SubmitPasswordResetRequestAsync(
            string normalizedIdentifier,
            string identifierHash,
            string? requesterIp,
            DateTime now,
            CancellationToken cancellationToken)
        {
            Identifier = normalizedIdentifier;
            IdentifierHash = identifierHash;
            RequesterIp = requesterIp;
            return Task.FromResult(submission);
        }

        public Task<IReadOnlyList<PasswordResetRequestInfo>> ListPasswordResetRequestsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<PasswordResetRequestInfo>>([]);

        public Task<PasswordResetDecisionResult> ReviewPasswordResetRequestAsync(
            int requestId, int reviewerId, bool approve, string reason, string? tokenHash, DateTime now,
            CancellationToken cancellationToken) => throw new NotImplementedException();

        public Task<bool> HasValidPasswordResetTokenAsync(string tokenHash, DateTime now, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> CompletePasswordResetAsync(
            string tokenHash, string passwordHash, DateTime now, CancellationToken cancellationToken) =>
            Task.FromResult(false);
    }
}
