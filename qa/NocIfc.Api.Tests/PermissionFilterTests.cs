using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class PermissionFilterTests
{
    [Fact]
    public async Task MissingPageGrantReturnsStructured403()
    {
        var context = await AuthenticatedContext(new AuthenticatedUser(8, "operator", "analyst", [], [], []));
        var filter = new AuthorizationFilterContext(
            new ActionContext(context, new RouteData(), new ActionDescriptor()), []);

        new RequirePageAttribute("Settings & Admin").OnAuthorization(filter);

        var result = Assert.IsType<ObjectResult>(filter.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("permission_denied", detail.GetProperty("code").GetString());
        Assert.Equal("page", detail.GetProperty("scope").GetString());
        Assert.Equal("Settings & Admin", detail.GetProperty("permission").GetString());
    }

    [Fact]
    public async Task MissingActionGrantReturnsStructured403()
    {
        var context = await AuthenticatedContext(new AuthenticatedUser(8, "operator", "analyst", [], [], []));
        var filter = new AuthorizationFilterContext(
            new ActionContext(context, new RouteData(), new ActionDescriptor()), []);

        new RequireActionAttribute("Action: Manage Roles").OnAuthorization(filter);

        var result = Assert.IsType<ObjectResult>(filter.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("permission_denied", detail.GetProperty("code").GetString());
        Assert.Equal("action", detail.GetProperty("scope").GetString());
        Assert.Equal("Action: Manage Roles", detail.GetProperty("permission").GetString());
    }

    [Fact]
    public async Task AdministratorOverrideAllowsPageAndActionGrants()
    {
        var context = await AuthenticatedContext(new AuthenticatedUser(1, "admin", "administrator", [], [], []));
        var filter = new AuthorizationFilterContext(
            new ActionContext(context, new RouteData(), new ActionDescriptor()), []);

        new RequirePageAttribute("Settings & Admin").OnAuthorization(filter);
        new RequireActionAttribute("Action: Manage Users").OnAuthorization(filter);

        Assert.Null(filter.Result);
    }

    [Fact]
    public async Task RequireAnyActionAllowsOneGrantAndReportsAllMissingAlternatives()
    {
        const string first = "Tab: Regional Grid -> Geospatial Map";
        const string second = "Tab: Regional Grid -> Location Matrix";
        var allowedContext = await AuthenticatedContext(
            new AuthenticatedUser(8, "operator", "analyst", [], [second], []));
        var allowedFilter = new AuthorizationFilterContext(
            new ActionContext(allowedContext, new RouteData(), new ActionDescriptor()), []);
        new RequireAnyActionAttribute(first, second).OnAuthorization(allowedFilter);
        Assert.Null(allowedFilter.Result);

        var deniedContext = await AuthenticatedContext(new AuthenticatedUser(8, "operator", "analyst", [], [], []));
        var deniedFilter = new AuthorizationFilterContext(
            new ActionContext(deniedContext, new RouteData(), new ActionDescriptor()), []);
        new RequireAnyActionAttribute(first, second).OnAuthorization(deniedFilter);

        var result = Assert.IsType<ObjectResult>(deniedFilter.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("tab", detail.GetProperty("scope").GetString());
        Assert.Equal($"{first} or {second}", detail.GetProperty("permission").GetString());
        Assert.Equal($"Missing tab permission: {first} or {second}", detail.GetProperty("message").GetString());
    }

    [Fact]
    public async Task AdministratorOnlyFilterUsesRoleScopedStructured403()
    {
        var context = await AuthenticatedContext(new AuthenticatedUser(8, "manager", "analyst", [], ["Action: Manage Roles"], []));
        var filter = new AuthorizationFilterContext(
            new ActionContext(context, new RouteData(), new ActionDescriptor()), []);

        new RequireAdministratorAttribute().OnAuthorization(filter);

        var result = Assert.IsType<ObjectResult>(filter.Result);
        Assert.Equal(StatusCodes.Status403Forbidden, result.StatusCode);
        using var body = JsonDocument.Parse(JsonSerializer.Serialize(result.Value));
        var detail = body.RootElement.GetProperty("detail");
        Assert.Equal("role", detail.GetProperty("scope").GetString());
        Assert.Equal("Administrator", detail.GetProperty("permission").GetString());
        Assert.Equal("Administrator role required", detail.GetProperty("message").GetString());
    }

    private static async Task<DefaultHttpContext> AuthenticatedContext(AuthenticatedUser user)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/user-admin/roles";
        context.Request.Headers["Authorization"] = "Bearer test-token";
        var middleware = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await middleware.InvokeAsync(context, new StubSessionResolver(user));
        return context;
    }

    private sealed class StubSessionResolver(AuthenticatedUser user) : IUserSessionResolver
    {
        public Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult<AuthenticatedUser?>(user);
    }
}
