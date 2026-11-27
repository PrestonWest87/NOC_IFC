using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Authentication;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
using NocIfc.Infrastructure.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class SessionAuthenticationMiddlewareTests
{
    [Fact]
    public async Task AcceptsBearerSessionAndSetsCurrentUser()
    {
        var user = new AuthenticatedUser(7, "operator", "analyst", [], [], []);
        var resolver = new StubSessionResolver(user);
        var context = CreateContext("/api/v1/permissions/catalog");
        context.Request.Headers["Authorization"] = "Bearer session-token";
        var nextCalled = false;
        var middleware = new SessionAuthenticationMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            NullLogger<SessionAuthenticationMiddleware>.Instance);

        await middleware.InvokeAsync(context, resolver);

        Assert.True(nextCalled);
        Assert.Equal("session-token", resolver.LastToken);
        Assert.Same(user, AuthenticatedUserContext.GetUser(context));
    }

    [Fact]
    public async Task RejectsUnknownSessionWithStructured401()
    {
        var context = CreateContext("/api/v1/permissions/catalog");
        context.Request.Headers["Authorization"] = "Bearer expired-token";
        context.Response.Body = new MemoryStream();
        var middleware = new SessionAuthenticationMiddleware(
            _ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);

        await middleware.InvokeAsync(context, new StubSessionResolver(null));

        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        Assert.Equal("unauthenticated", body.RootElement.GetProperty("detail").GetProperty("code").GetString());
    }

    [Fact]
    public async Task PublicLoginBypassesSessionResolution()
    {
        var context = CreateContext("/api/v1/auth/login");
        var resolver = new StubSessionResolver(null);
        var nextCalled = false;
        var middleware = new SessionAuthenticationMiddleware(
            _ => { nextCalled = true; return Task.CompletedTask; },
            NullLogger<SessionAuthenticationMiddleware>.Instance);

        await middleware.InvokeAsync(context, resolver);

        Assert.True(nextCalled);
        Assert.Null(resolver.LastToken);
    }

    [Fact]
    public async Task RestoreMaintenanceBlocksApiRequestsButAllowsRestoreStatusAndStartRoute()
    {
        var workspace = Directory.CreateTempSubdirectory("nocifc-restore-middleware-");
        var databasePath = Path.Combine(workspace.FullName, "database.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var control = new SqliteRestoreMaintenanceControl(
                new SqliteConnectionFactory($"sqlite:///{databasePath}"));
            control.BeginRestore("stage-0123456789abcdef0123456789abcdef.nocbackup", "admin");
            var middleware = new SessionAuthenticationMiddleware(
                _ => Task.CompletedTask, NullLogger<SessionAuthenticationMiddleware>.Instance);

            var blocked = CreateContext("/api/v1/permissions/catalog");
            blocked.Response.Body = new MemoryStream();
            await middleware.InvokeAsync(blocked, new StubSessionResolver(null), control);
            Assert.Equal(StatusCodes.Status503ServiceUnavailable, blocked.Response.StatusCode);
            Assert.Equal(0, control.ActiveApiRequests);

            var restoreStatus = CreateContext("/api/v1/restore-status");
            await middleware.InvokeAsync(restoreStatus, new StubSessionResolver(null), control);
            Assert.Equal(StatusCodes.Status200OK, restoreStatus.Response.StatusCode);

            var restoreStart = CreateContext("/api/v1/admin/backups/staged/stage-0123456789abcdef0123456789abcdef.nocbackup/restore");
            restoreStart.Request.Headers["Authorization"] = "Bearer admin-session";
            var user = new AuthenticatedUser(1, "admin", "administrator", [], [], []);
            var restoreStartCalled = false;
            await new SessionAuthenticationMiddleware(
                _ => { restoreStartCalled = true; return Task.CompletedTask; },
                NullLogger<SessionAuthenticationMiddleware>.Instance)
                .InvokeAsync(restoreStart, new StubSessionResolver(user), control);
            Assert.True(restoreStartCalled);
            Assert.Equal(0, control.ActiveApiRequests);
        }
        finally
        {
            Directory.Delete(workspace.FullName, true);
        }
    }

    private static DefaultHttpContext CreateContext(string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        return context;
    }

    private sealed class StubSessionResolver(AuthenticatedUser? user) : IUserSessionResolver
    {
        public string? LastToken { get; private set; }

        public Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken)
        {
            LastToken = token;
            return Task.FromResult(user);
        }
    }
}
