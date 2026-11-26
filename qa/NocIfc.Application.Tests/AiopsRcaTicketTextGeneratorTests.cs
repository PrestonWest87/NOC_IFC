using NocIfc.Application.Features.AIOps;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiopsRcaTicketTextGeneratorTests
{
    [Fact]
    public void FormatsSanitizedTicketWithCentralTimesAndAffectedDomains()
    {
        var ticket = AiopsRcaTicketTextGenerator.Generate(new AiopsTicketTextInput(
            "Central NOC",
            "P1? - CRITICAL 😀",
            "Carrier? outage 😀",
            "2026-07-01T18:00:00Z",
            "Central",
            ["INTERNET", "COMMS_EQUIPMENT"],
            [new AiopsTicketTextAlert("2026-07-01T19:00:00Z", "router-1", "192.0.2.1", "Down", "network")]));

        Assert.Contains("District: Central", ticket);
        Assert.Contains("07/01/2026 01:00 PM CDT", ticket);
        Assert.Contains("affecting Internet, Comms Equipment", ticket);
        Assert.Contains("PRIORITY: P1 - CRITICAL\nCarrier outage", ticket);
        Assert.Contains("[1] router-1 (192.0.2.1) - Down | network | Since: 2026-07-01 14:00:00", ticket);
        Assert.DoesNotContain("?", ticket);
        Assert.DoesNotContain("😀", ticket);
    }
}
