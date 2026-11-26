using System.Text.Json.Nodes;
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
        Assert.Contains("EPSG:4326", coverage.ArkansasBounds, StringComparison.Ordinal);
        Assert.True(coverage.IncludesArkansasPoint(-92.2896, 34.7465));
        Assert.True(coverage.IncludesBorderPoint(-93.75, 32.5252));
        Assert.False(coverage.IncludesBorderPoint(-92.2896, 34.7465));
        Assert.Contains("05001", coverage.GetRegionalCounties().Keys);
    }

    [Fact]
    public void ClassifiesAlertGeometryAgainstArkansasAndBorderBuffer()
    {
        var coverage = ArkansasFireCoverage.LoadBundled();

        Assert.True(coverage.TryGetAlertGeometryScope(Point(-92.2896, 34.7465), out var arkansasScope));
        Assert.Equal("arkansas", arkansasScope);
        Assert.True(coverage.TryGetAlertGeometryScope(Point(-93.75, 32.5252), out var borderScope));
        Assert.Equal("border", borderScope);
        Assert.True(coverage.TryGetAlertGeometryScope(Point(-80, 40), out var outsideScope));
        Assert.Null(outsideScope);
        Assert.True(coverage.TryGetAlertGeometryScope(Polygon((-95, 32), (-89, 32), (-89, 37), (-95, 37), (-95, 32)), out arkansasScope));
        Assert.Equal("arkansas", arkansasScope);
    }

    private static JsonObject Point(double longitude, double latitude) => new()
    {
        ["type"] = "Point",
        ["coordinates"] = new JsonArray(longitude, latitude),
    };

    private static JsonObject Polygon(params (double Longitude, double Latitude)[] points) => new()
    {
        ["type"] = "Polygon",
        ["coordinates"] = new JsonArray(new JsonArray(points.Select(point =>
            (JsonNode?)new JsonArray(point.Longitude, point.Latitude)).ToArray())),
    };
}
