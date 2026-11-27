using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using NocIfc.Api.Contracts;
using NocIfc.Api.Controllers;
using NocIfc.Api.Middleware;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class OperationalEmailControllerTests
{
    [Fact]
    public async Task SendRejectsUnknownRequestFieldsAsUnprocessable()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/operational-email/send";
        context.Request.Headers.Authorization = "Bearer test-session";
        var middleware = new SessionAuthenticationMiddleware(_ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance);
        await middleware.InvokeAsync(context, new TestSessionResolver());

        var controller = new OperationalEmailController(null!, null!, null!, null!, null!)
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
        var body = JsonNode.Parse("""
            { "template_key": "maintenance_notice", "unexpected": true }
            """)!.AsObject();

        var result = await controller.Send(body, CancellationToken.None);

        var error = Assert.IsType<UnprocessableEntityObjectResult>(result);
        Assert.Contains("Unsupported operational email field", error.Value?.ToString() ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void SendResponseUsesFrontendSnakeCaseAndOmitsGroupedFieldsForSingleMessages()
    {
        var response = OperationalEmailSendResponse.From(new OperationalEmailSendResult(
            "sent", "Email sent successfully.", 12, 18, new DateTime(2026, 11, 27, 18, 30, 0, DateTimeKind.Utc),
            false, null, null, null, null, null, null));
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(response,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)));
        var root = json.RootElement;

        Assert.Equal(12, root.GetProperty("email_id").GetInt32());
        Assert.Equal(18, root.GetProperty("delivery_id").GetInt32());
        Assert.Equal("sent", root.GetProperty("status").GetString());
        Assert.False(root.TryGetProperty("grouped", out _));
    }

    [Fact]
    public async Task ScheduleRejectsNaiveOneTimeTimestamp()
    {
        var context = new DefaultHttpContext();
        context.Request.Path = "/api/v1/operational-email/schedule";
        context.Request.Headers.Authorization = "Bearer test-session";
        await new SessionAuthenticationMiddleware(_ => Task.CompletedTask,
            NullLogger<SessionAuthenticationMiddleware>.Instance)
            .InvokeAsync(context, new TestSessionResolver());
        var controller = new OperationalEmailController(null!, null!, null!, null!, null!)
        {
            ControllerContext = new ControllerContext { HttpContext = context },
        };
        var body = JsonNode.Parse("""
            {
              "template_key": "morning_report",
              "to": "ops@example.com",
              "schedule": { "schedule_type": "once", "scheduled_at": "2026-11-28T08:30" }
            }
            """)!.AsObject();

        var result = await controller.Schedule(body, CancellationToken.None);

        var error = Assert.IsType<UnprocessableEntityObjectResult>(result);
        Assert.Contains("with a time zone", error.Value?.ToString() ?? "", StringComparison.Ordinal);
    }

    private sealed class TestSessionResolver : IUserSessionResolver
    {
        public Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken) =>
            Task.FromResult<AuthenticatedUser?>(token == "test-session"
                ? new AuthenticatedUser(7, "operator", "analyst", ["Operational Email"], [], [])
                : null);
    }
}
