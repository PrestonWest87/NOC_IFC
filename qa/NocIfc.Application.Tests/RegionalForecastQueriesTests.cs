using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalForecastQueriesTests
{
    [Fact]
    public async Task ReturnsProviderPeriodsAndRejectsInvalidCoordinates()
    {
        var provider = new StubForecastProvider("[{\"name\":\"Tonight\"}]");
        var queries = new RegionalForecastQueries(provider);

        var periods = await queries.GetAsync(34.8, -92.2, CancellationToken.None);

        Assert.IsType<JsonArray>(periods);
        Assert.Equal(34.8, provider.Latitude);
        Assert.Equal(-92.2, provider.Longitude);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetAsync(91, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetAsync(0, double.NaN, CancellationToken.None));
    }

    private sealed class StubForecastProvider(string? json) : INwsForecastProvider
    {
        public double Latitude { get; private set; }
        public double Longitude { get; private set; }

        public Task<string?> GetForecastPeriodsJsonAsync(
            double latitude,
            double longitude,
            CancellationToken cancellationToken)
        {
            Latitude = latitude;
            Longitude = longitude;
            return Task.FromResult(json);
        }
    }
}
