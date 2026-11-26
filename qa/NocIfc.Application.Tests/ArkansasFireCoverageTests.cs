using NocIfc.Infrastructure.Integrations.Weather;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ArkansasFireCoverageTests
{
    [Fact]
    public void UsesBundledArkansasGeometryAndFiftyMileNeighborBuffer()
    {
        var coverage = ArkansasFireCoverage.LoadBundled();

        Assert.True(coverage.IncludesPoint(-92.2896, 34.7465));
        Assert.True(coverage.IncludesPoint(-93.75, 32.5252));
        Assert.False(coverage.IncludesPoint(-93.75, 31.5));
        Assert.False(coverage.IncludesPoint(-80, 40));
        Assert.Contains("EPSG:4326", coverage.WfsBounds, StringComparison.Ordinal);
    }
}
