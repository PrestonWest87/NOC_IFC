using System.Text.Json;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class FailedLoginAlertTextTests
{
    [Fact]
    public void IncludesQuotedUsernamesAndExplicitlyExcludesPasswords()
    {
        var alert = new FailedLoginAlert(
            "security@example.com",
            2,
            5,
            new DateTime(2026, 11, 25, 12, 0, 0, DateTimeKind.Utc),
            [new FailedLoginAttemptEntry("unknown\"user", "192.0.2.10", new DateTime(2026, 11, 25, 11, 59, 0, DateTimeKind.Utc))]);

        var (subject, body) = FailedLoginAlertText.Format(alert);

        Assert.Equal("Multiple failed login attempts detected", subject);
        Assert.Contains(JsonSerializer.Serialize("unknown\"user"), body);
        Assert.Contains("Passwords are not collected or included in this alert.", body);
    }
}
