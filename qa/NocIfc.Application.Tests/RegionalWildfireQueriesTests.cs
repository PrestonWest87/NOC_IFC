using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalWildfireQueriesTests
{
    [Fact]
    public async Task FiltersIncidentsAndPerimetersToTheRequestedViewport()
    {
        var provider = new StubWildfireProvider("""
            {
              "incidents": [
                {"name":"inside","lon":-93,"lat":34},
                {"name":"outside","lon":-80,"lat":40},
                {"name":"invalid","lon":"bad","lat":34}
              ],
              "perimeters": [
                {"name":"inside","geometry":{"type":"Point","coordinates":[-93,34]}},
                {"name":"outside","geometry":{"type":"Point","coordinates":[-80,40]}},
                {"name":"no geometry"}
              ],
              "footprints": [],
              "meta": {"status":"stale"}
            }
            """);
        var queries = new RegionalWildfireQueries(provider);

        var result = await queries.GetAsync("-94,33,-92,35", CancellationToken.None);

        Assert.Equal(new[] { "inside" }, result!["incidents"]!.AsArray()
            .Select(fire => fire!["name"]!.GetValue<string>()));
        Assert.Equal(new[] { "inside", "no geometry" }, result["perimeters"]!.AsArray()
            .Select(perimeter => perimeter!["name"]!.GetValue<string>()));
        Assert.Equal("stale", result["meta"]!["status"]!.GetValue<string>());
        Assert.Equal(1, provider.Calls);
        await Assert.ThrowsAsync<ArgumentException>(() => queries.GetAsync("invalid", CancellationToken.None));
        Assert.Equal(1, provider.Calls);
    }

    private sealed class StubWildfireProvider(string payload) : IRegionalWildfireProvider
    {
        public int Calls { get; private set; }
        public Task<string> GetActiveWildfiresJsonAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(payload);
        }
    }
}
