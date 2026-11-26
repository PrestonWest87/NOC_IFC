using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Authentication;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;
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
