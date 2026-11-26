using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RoleQueriesTests
{
    private static readonly string[] ElevatedActions =
    [
        "Action: Manage Users",
        "Action: Manage Roles",
        "Action: Review Account Recovery Requests",
        "Action: Approve Recovery Email Changes",
    ];

    [Fact]
    public async Task DelegatedManagersCannotAssignAdministratorOrRecoveryRoles()
    {
        var roles = new StubRoleDirectory(
        [
            Role("admin"),
            Role("administrator"),
            Role("user-manager", ["Action: Manage Users"]),
            Role("reviewer", ["Action: Review Account Recovery Requests"]),
            Role("analyst"),
        ]);
        var service = new RoleQueries(roles);
        var actor = new AuthenticatedUser(4, "manager", "analyst", [], ElevatedActions, []);

        var result = await service.ListAssignableRolesAsync(actor, CancellationToken.None);

        Assert.Equal(new[] { "analyst" }, result.Select(role => role.Name));
    }

    [Fact]
    public async Task BuiltInAdministratorCanAssignAllRoles()
    {
        var roles = new StubRoleDirectory([Role("admin"), Role("administrator"), Role("analyst")]);
        var service = new RoleQueries(roles);
        var actor = new AuthenticatedUser(1, "admin", "administrator", [], [], []);

        var result = await service.ListAssignableRolesAsync(actor, CancellationToken.None);

        Assert.Equal(3, result.Count);
    }

    [Fact]
    public async Task DelegatedRoleEditorsMaySeeButCannotAssignElevatedDefinitions()
    {
        var roles = new StubRoleDirectory(
        [
            Role("admin"),
            Role("user-manager", ["Action: Manage Users"]),
            Role("analyst"),
        ]);
        var service = new RoleQueries(roles);
        var actor = new AuthenticatedUser(4, "manager", "analyst", [], ElevatedActions, []);

        var definitions = await service.ListRoleDefinitionsAsync(actor, CancellationToken.None);
        var assignable = await service.ListAssignableRolesAsync(actor, CancellationToken.None);

        Assert.Equal(new[] { "user-manager", "analyst" }, definitions.Select(role => role.Name));
        Assert.Equal(new[] { "analyst" }, assignable.Select(role => role.Name));
    }

    private static RoleDefinition Role(string name, IReadOnlyList<string>? actions = null) =>
        new(1, name, [], actions ?? [], []);

    private sealed class StubRoleDirectory(IReadOnlyList<RoleDefinition> roles) : IRoleDirectory
    {
        public Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(roles);
    }
}
