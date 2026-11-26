using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Authentication;
using NocIfc.Api.Contracts;
using NocIfc.Api.Controllers;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using NocIfc.Infrastructure.Security;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class UserAdminControllerTests
{
    [Fact]
    public async Task RolesControllerReturnsSnakeCaseRoleGrantFields()
    {
        var user = new AuthenticatedUser(1, "admin", "administrator", [], [], []);
        var controller = Controller(
        [new RoleDefinition(2, "analyst", ["Threat Telemetry"], ["Action: Pin Articles"], ["NOC"])]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/roles";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = context,
        };

        var response = await controller.ListAssignableRoles(CancellationToken.None);
        var result = Assert.IsType<OkObjectResult>(response.Result);
        var json = JsonSerializer.SerializeToElement(result.Value);
        var role = Assert.Single(json.EnumerateArray());

        Assert.Equal(2, role.GetProperty("id").GetInt32());
        Assert.Equal("analyst", role.GetProperty("name").GetString());
        Assert.Equal("Threat Telemetry", role.GetProperty("allowed_pages")[0].GetString());
        Assert.Equal("Action: Pin Articles", role.GetProperty("allowed_actions")[0].GetString());
        Assert.Equal("NOC", role.GetProperty("allowed_site_types")[0].GetString());
    }

    [Fact]
    public async Task DelegatedRoleDefinitionsHideAdministratorsButRetainElevatedDefinitions()
    {
        var user = new AuthenticatedUser(3, "manager", "analyst", [], ["Action: Manage Roles"], []);
        var controller = Controller(
        [
            new RoleDefinition(1, "admin", [], [], []),
            new RoleDefinition(2, "user-manager", [], ["Action: Manage Users"], []),
            new RoleDefinition(3, "analyst", [], [], []),
        ]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/role-definitions";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.ListRoleDefinitions(CancellationToken.None);
        var result = Assert.IsType<OkObjectResult>(response.Result);
        var json = JsonSerializer.SerializeToElement(result.Value);

        Assert.Equal(
            new[] { "user-manager", "analyst" },
            json.EnumerateArray().Select(role => role.GetProperty("name").GetString()));
    }

    [Fact]
    public async Task SiteTypesControllerReturnsMergedCatalog()
    {
        var user = new AuthenticatedUser(3, "manager", "manager", [], ["Action: Manage Roles"], []);
        var controller = Controller([]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/site-types";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.ListSiteTypes(CancellationToken.None);
        var result = Assert.IsType<OkObjectResult>(response.Result);
        var json = JsonSerializer.SerializeToElement(result.Value);

        Assert.Equal("NOC", json[0].GetString());
        Assert.Equal("Custom", json[json.GetArrayLength() - 1].GetString());
    }

    [Fact]
    public async Task UserDirectoryReturnsOnlyTheSanitizedContractFields()
    {
        var user = new AuthenticatedUser(3, "manager", "manager", [], ["Action: Manage Users"], []);
        var row = new UserDirectoryEntry(
            8, "alice", "Alice", null, null, "alice@example.com", true, "verified", null,
            "individual", "analyst", true, null, null, null, false);
        var controller = Controller([], [row]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/users";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.ListUsers(CancellationToken.None);
        var result = Assert.IsType<OkObjectResult>(response.Result);
        var json = JsonSerializer.SerializeToElement(result.Value);
        var entry = Assert.Single(json.EnumerateArray());

        Assert.Equal("alice", entry.GetProperty("username").GetString());
        Assert.Equal("verified", entry.GetProperty("email_status").GetString());
        Assert.False(entry.TryGetProperty("password_hash", out _));
        Assert.False(entry.TryGetProperty("session_token", out _));
    }

    [Fact]
    public async Task AdministratorCanCreateRoleThroughController()
    {
        var user = new AuthenticatedUser(1, "admin", "admin", [], [], []);
        var controller = Controller([]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/roles";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.CreateRole(
            new RoleDefinitionRequest
            {
                Name = "regional-operator",
                AllowedPages = ["Global Dashboards"],
                AllowedActions = ["Action: Generate Reports"],
                AllowedSiteTypes = ["NOC"],
            },
            CancellationToken.None);

        var result = Assert.IsType<OkObjectResult>(response);
        var body = JsonSerializer.SerializeToElement(result.Value);
        Assert.Equal("created", body.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AdministratorCanCreateDisplayAccountThroughController()
    {
        var user = new AuthenticatedUser(1, "admin", "admin", [], [], []);
        var controller = Controller([]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/display-accounts";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.CreateDisplayAccount(
            new DisplayAccountRequest
            {
                Username = "wall-screen",
                Password = "wall-screen-password-123",
                Role = "viewer",
                FullName = "Wall Screen",
            },
            CancellationToken.None);

        var result = Assert.IsType<OkObjectResult>(response);
        var body = JsonSerializer.SerializeToElement(result.Value);
        Assert.Equal("created", body.GetProperty("status").GetString());
        Assert.Equal(10, body.GetProperty("user_id").GetInt32());
        Assert.Equal("display", body.GetProperty("account_type").GetString());
    }

    [Fact]
    public async Task DelegatedRoleEditorCannotEscalateRoleGrants()
    {
        var user = new AuthenticatedUser(
            3, "manager", "role-editor", ["Settings & Admin"], ["Action: Manage Roles"], ["NOC"]);
        var controller = Controller([]);
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/roles";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.CreateRole(
            new RoleDefinitionRequest
            {
                Name = "elevated",
                AllowedPages = ["Settings & Admin"],
                AllowedActions = ["Action: Manage Users"],
                AllowedSiteTypes = ["NOC"],
            },
            CancellationToken.None);

        var result = Assert.IsType<ObjectResult>(response);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        Assert.Equal("permission_denied", body.RootElement.GetProperty("detail").GetProperty("code").GetString());
    }

    [Fact]
    public async Task DelegatedManagerCannotDisableAnAdministratorAccount()
    {
        var user = new AuthenticatedUser(3, "manager", "manager", [], ["Action: Manage Users"], []);
        var controller = Controller(
            [new RoleDefinition(1, "admin", [], [], [])],
            target: new UserAdminTarget(8, "protected-admin", "admin", "individual", "admin@example.com", true));
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/users/protected-admin/status";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.SetUserStatus(
            "protected-admin",
            new UserStatusRequest { IsActive = false },
            CancellationToken.None);

        var result = Assert.IsType<ObjectResult>(response);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("permission_denied", detail.GetProperty("code").GetString());
        Assert.Equal("role", detail.GetProperty("scope").GetString());
        Assert.Equal("Administrator", detail.GetProperty("permission").GetString());
    }

    [Fact]
    public async Task DelegatedManagerCannotAssistedResetAnIndividualAccount()
    {
        var user = new AuthenticatedUser(3, "manager", "manager", [], ["Action: Manage Users"], []);
        var controller = Controller(
            [],
            target: new UserAdminTarget(9, "alice", "analyst", "individual", "alice@example.com", true));
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/users/alice/administrator-reset";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var authentication = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await authentication.InvokeAsync(context, new StubSessionResolver(user));
        controller.ControllerContext = new ControllerContext { HttpContext = context };

        var response = await controller.AdministratorReset(
            "alice", new AdministratorResetRequest { NewPassword = "replacement password" }, CancellationToken.None);

        var result = Assert.IsType<ObjectResult>(response);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("Action: Review Account Recovery Requests", detail.GetProperty("permission").GetString());
    }

    private static UserAdminController Controller(
        IReadOnlyList<RoleDefinition> roles,
        IReadOnlyList<UserDirectoryEntry>? users = null,
        UserAdminTarget? target = null)
    {
        var roleDirectory = new StubRoleDirectory(roles);
        var siteTypes = new SiteTypeQueries(new StubSiteTypeDirectory(["Custom", "NOC"]));
        return new UserAdminController(
            new RoleQueries(roleDirectory),
            siteTypes,
            new UserDirectoryQueries(new StubUserDirectory(users ?? [])),
            new RoleCommands(roleDirectory, roleDirectory, siteTypes),
            new UserAdminCommands(new StubUserAdminStore(target), roleDirectory, new BCryptPasswordHasher()));
    }

    private sealed class StubRoleDirectory(IReadOnlyList<RoleDefinition> roles) : IRoleDirectory, IRoleWriter
    {
        public Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(roles);

        public Task<bool> CreateAsync(RoleDefinition role, CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<bool> UpdateAsync(RoleDefinition role, CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class StubSiteTypeDirectory(IReadOnlyList<string> siteTypes) : ISiteTypeDirectory
    {
        public Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(siteTypes);
    }

    private sealed class StubUserDirectory(IReadOnlyList<UserDirectoryEntry> users) : IUserDirectory
    {
        public Task<IReadOnlyList<UserDirectoryEntry>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult(users);
    }

    private sealed class StubUserAdminStore(UserAdminTarget? target) : IUserAdminStore
    {
        public Task<UserAdminTarget?> FindTargetAsync(string username, CancellationToken cancellationToken) =>
            Task.FromResult(target?.Username == username ? target : null);

        public Task<bool> ChangeRoleAsync(UserAdminTarget user, string role, int actorUserId, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> SetActiveAsync(UserAdminTarget user, bool isActive, int actorUserId, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> RevokeSessionsAsync(UserAdminTarget user, int actorUserId, CancellationToken cancellationToken) =>
            Task.FromResult(true);

        public Task<bool> AdministratorResetAsync(
            UserAdminTarget user,
            string passwordHash,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<bool> UpdateIdentityAsync(
            UserAdminTarget user,
            string fullName,
            string jobTitle,
            string contactInfo,
            int actorUserId,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<bool> SetAccountTypeAsync(
            UserAdminTarget user,
            string accountType,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<DisplayAccountCreateResult> CreateDisplayAccountAsync(
            string username,
            string passwordHash,
            string role,
            string fullName,
            int actorUserId,
            DateTime now,
            CancellationToken cancellationToken) =>
            Task.FromResult(new DisplayAccountCreateResult(DisplayAccountCreateStatus.Created, 10));

        public Task<RegistrationInviteCreateResult> CreateRegistrationInviteAsync(
            string username,
            string email,
            string normalizedEmail,
            string role,
            string tokenHash,
            string createdBy,
            int ttlHours,
            DateTime now,
            CancellationToken cancellationToken) =>
            Task.FromResult(new RegistrationInviteCreateResult(
                RegistrationInviteCreateStatus.Created, 1, now.AddHours(ttlHours)));

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

    private sealed class StubSessionResolver(AuthenticatedUser user) : IUserSessionResolver
    {
        public Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult<AuthenticatedUser?>(user);
    }
}
