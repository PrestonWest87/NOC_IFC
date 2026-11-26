using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RoleCommandsTests
{
    [Fact]
    public async Task AdministratorCreatesRoleAfterGrantValidationAndDeduplication()
    {
        var store = new StubRoleStore([]);
        var commands = Commands(store);

        var created = await commands.CreateAsync(
            Admin(),
            new RoleDefinitionInput(
                "  field-operator  ",
                ["Global Dashboards", "Global Dashboards"],
                ["Action: Generate Reports", "Action: Generate Reports"],
                ["NOC", "NOC"]),
            CancellationToken.None);

        Assert.True(created);
        var role = Assert.Single(store.Created);
        Assert.Equal("field-operator", role.Name);
        Assert.Equal(new[] { "Global Dashboards" }, role.AllowedPages);
        Assert.Equal(new[] { "Action: Generate Reports" }, role.AllowedActions);
        Assert.Equal(new[] { "NOC" }, role.AllowedSiteTypes);
    }

    [Fact]
    public async Task DelegatedEditorCannotGrantPermissionsOutsideItsOwnRole()
    {
        var store = new StubRoleStore([]);
        var commands = Commands(store);
        var actor = new AuthenticatedUser(
            2,
            "role-editor",
            "role-editor",
            ["Settings & Admin"],
            ["Action: Manage Roles"],
            ["NOC"]);

        var error = await Assert.ThrowsAsync<RoleCommandException>(() => commands.CreateAsync(
            actor,
            new RoleDefinitionInput("limited", ["Settings & Admin"], ["Action: Manage Users"], ["NOC"]),
            CancellationToken.None));

        Assert.Equal(403, error.StatusCode);
        Assert.True(error.PermissionDenied);
        Assert.Empty(store.Created);
    }

    [Fact]
    public async Task RoleUpdateMayRetainButCannotAddUnknownLegacyGrants()
    {
        var existing = new RoleDefinition(5, "legacy", ["Retired Page"], ["Action: Legacy"], ["Old Zone"]);
        var store = new StubRoleStore([existing]);
        var commands = Commands(store);
        var unchangedLegacyGrants = new RoleDefinitionInput(
            "legacy", ["Retired Page"], ["Action: Legacy"], ["Old Zone"]);

        Assert.True(await commands.UpdateAsync(Admin(), "legacy", unchangedLegacyGrants, CancellationToken.None));
        Assert.Equal("Old Zone", Assert.Single(store.Updated).AllowedSiteTypes[0]);

        var error = await Assert.ThrowsAsync<RoleCommandException>(() => commands.UpdateAsync(
            Admin(),
            "legacy",
            new RoleDefinitionInput("legacy", ["Retired Page"], ["Action: Legacy"], ["Old Zone", "Unknown Zone"]),
            CancellationToken.None));
        Assert.Equal(400, error.StatusCode);
        Assert.Contains("unknown site type", error.Message);
    }

    private static RoleCommands Commands(StubRoleStore store) =>
        new(store, store, new SiteTypeQueries(new StubSiteTypeDirectory(["NOC", "SOC"])));

    private static AuthenticatedUser Admin() =>
        new(1, "admin", "administrator", [], [], []);

    private sealed class StubRoleStore(IReadOnlyList<RoleDefinition> roles) : IRoleDirectory, IRoleWriter
    {
        public List<RoleDefinition> Created { get; } = [];
        public List<RoleDefinition> Updated { get; } = [];

        public Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(roles);

        public Task<bool> CreateAsync(RoleDefinition role, CancellationToken cancellationToken)
        {
            Created.Add(role);
            return Task.FromResult(true);
        }

        public Task<bool> UpdateAsync(RoleDefinition role, CancellationToken cancellationToken)
        {
            Updated.Add(role);
            return Task.FromResult(true);
        }
    }

    private sealed class StubSiteTypeDirectory(IReadOnlyList<string> siteTypes) : ISiteTypeDirectory
    {
        public Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(siteTypes);
    }
}
