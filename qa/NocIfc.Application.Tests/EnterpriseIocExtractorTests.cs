using NocIfc.Application.Features.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class EnterpriseIocExtractorTests
{
    [Fact]
    public void RefangsAndExtractsUniqueTypedPublicIndicatorsWithContext()
    {
        var raw = "hxxps://malicious[.]example.net/campaign CVE-2026-12345 T1059 admin@evil.test 1.2.3.4 10.1.2.3 8.8.8.8";

        var indicators = EnterpriseIocExtractor.Extract(raw);

        Assert.Contains(indicators, item => item.Type == "URL" && item.Indicator == "http://malicious.example.net/campaign");
        Assert.DoesNotContain(indicators, item => item.Type == "Domain" && item.Indicator == "malicious.example.net");
        Assert.Contains(indicators, item => item.Type == "CVE" && item.Indicator == "CVE-2026-12345");
        Assert.Contains(indicators, item => item.Type == "MITRE ATT&CK" && item.Indicator == "T1059");
        Assert.Contains(indicators, item => item.Type == "Email" && item.Indicator == "admin@evil.test");
        Assert.Contains(indicators, item => item.Type == "IPv4" && item.Indicator == "1.2.3.4");
        Assert.DoesNotContain(indicators, item => item.Type == "IPv4" && item.Indicator is "10.1.2.3" or "8.8.8.8");
        Assert.All(indicators, item => Assert.StartsWith("...", item.Context));
    }
}
