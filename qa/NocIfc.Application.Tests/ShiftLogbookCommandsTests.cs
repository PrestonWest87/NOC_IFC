using NocIfc.Application.Abstractions.Logbook;
using NocIfc.Application.Features.Logbook;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Logbook;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ShiftLogbookCommandsTests
{
    [Fact]
    public async Task NonHistoryUsersAreScopedToTheirRoleAndCurrentChicagoDay()
    {
        var store = new StubStore();
        var commands = new ShiftLogbookCommands(store);

        await commands.GetEntriesAsync(User("analyst", "analyst"), "All", "2000-01-01", "2030-01-01", CancellationToken.None);

        Assert.Equal("analyst", store.RoleFilter);
        Assert.NotNull(store.StartUtc);
        Assert.NotNull(store.EndExclusiveUtc);
        Assert.Equal(TimeSpan.FromDays(1), store.EndExclusiveUtc!.Value - store.StartUtc!.Value);
    }

    [Fact]
    public async Task CreationUsesAuthenticatedIdentityAndRestrictsNonAdminRole()
    {
        var store = new StubStore { FullName = "Jane Operator" };
        var commands = new ShiftLogbookCommands(store);

        await commands.CreateAsync(
            User("jane", "analyst"), "admin", "No Shift", "Completed network maintenance.", "2026-11-25", CancellationToken.None);

        Assert.Equal("Jane Operator", store.Analyst);
        Assert.Equal("analyst", store.AuthorRole);
        Assert.Equal("No Shift", store.ShiftPeriod);
        Assert.Equal("Completed network maintenance.", store.Content);
        Assert.Equal(new DateTime(2026, 11, 25), store.CreatedAtUtc!.Value.Date);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.CreateAsync(
            User("jane", "analyst"), "analyst", "Night", "Invalid period", null, CancellationToken.None));
    }

    [Fact]
    public async Task DeleteRestoreRequiresOwnershipOrManageGrant()
    {
        var store = new StubStore
        {
            Entry = new ShiftLogEntry(4, "Jane Operator", "analyst", null, "Morning", "note", null, false),
            FullName = "Jane Operator",
        };
        var commands = new ShiftLogbookCommands(store);

        var ownerResult = await commands.UpdateDeletedAsync(User("jane", "analyst"), 4, true, CancellationToken.None);
        var denied = await commands.UpdateDeletedAsync(User("other", "analyst"), 4, true, CancellationToken.None);
        var manager = User("manager", "manager", ["Action: Manage Shift Logs"]);
        var managerResult = await commands.UpdateDeletedAsync(manager, 4, false, CancellationToken.None);

        Assert.Equal("ok", ownerResult.Status);
        Assert.True(ownerResult.IsDeleted);
        Assert.True(denied.Forbidden);
        Assert.Equal("ok", managerResult.Status);
        Assert.False(managerResult.IsDeleted);
    }

    private static AuthenticatedUser User(string username, string role, IReadOnlyList<string>? actions = null) =>
        new(username == "other" ? 2 : 1, username, role, ["Shift Logbook"], actions ?? [], []);

    private sealed class StubStore : IShiftLogbookStore
    {
        public string? RoleFilter { get; private set; }
        public DateTime? StartUtc { get; private set; }
        public DateTime? EndExclusiveUtc { get; private set; }
        public string? FullName { get; init; }
        public string? Analyst { get; private set; }
        public string? AuthorRole { get; private set; }
        public string? ShiftPeriod { get; private set; }
        public string? Content { get; private set; }
        public DateTime? CreatedAtUtc { get; private set; }
        public ShiftLogEntry? Entry { get; set; }

        public Task<IReadOnlyList<ShiftLogEntry>> GetEntriesAsync(
            string? roleFilter,
            DateTime? startUtc,
            DateTime? endExclusiveUtc,
            CancellationToken cancellationToken)
        {
            RoleFilter = roleFilter;
            StartUtc = startUtc;
            EndExclusiveUtc = endExclusiveUtc;
            return Task.FromResult<IReadOnlyList<ShiftLogEntry>>([]);
        }

        public Task<IReadOnlyList<string>> GetRoleNamesAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task<string?> GetUserFullNameAsync(int userId, CancellationToken cancellationToken) =>
            Task.FromResult(userId == 1 ? FullName : null);

        public Task<int> CreateAsync(
            string analyst,
            string authorRole,
            string shiftPeriod,
            string content,
            DateTime createdAtUtc,
            DateTime shiftDateUtc,
            CancellationToken cancellationToken)
        {
            Analyst = analyst;
            AuthorRole = authorRole;
            ShiftPeriod = shiftPeriod;
            Content = content;
            CreatedAtUtc = createdAtUtc;
            return Task.FromResult(1);
        }

        public Task<ShiftLogEntry?> GetByIdAsync(int entryId, CancellationToken cancellationToken) =>
            Task.FromResult(Entry);

        public Task<bool> SetDeletedAsync(int entryId, bool isDeleted, CancellationToken cancellationToken)
        {
            if (Entry is null) return Task.FromResult(false);
            Entry = Entry with { IsDeleted = isDeleted };
            return Task.FromResult(true);
        }
    }
}
