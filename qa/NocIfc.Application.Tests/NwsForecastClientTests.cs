using System.Net;
using System.Text;
using NocIfc.Infrastructure.Integrations.Weather;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class NwsForecastClientTests
{
    [Fact]
    public async Task FetchesPointThenForecastAndCachesThePeriods()
    {
        var handler = new StubHandler(
        [
            """{"properties":{"forecast":"https://api.weather.gov/gridpoints/LZK/67,113/forecast"}}""",
            """{"properties":{"periods":[{"name":"Today","temperature":75}]}}""",
        ]);
        var client = new NwsForecastClient(
            new HttpClient(handler),
            new NwsForecastConfiguration("NOC-IFC/2.0 (https://ops.example)", "ops@example.test"));

        var periods = await client.GetForecastPeriodsJsonAsync(38.01234, -101.56789, CancellationToken.None);
        var cached = await client.GetForecastPeriodsJsonAsync(38.01234, -101.56789, CancellationToken.None);

        Assert.Equal("[{\"name\":\"Today\",\"temperature\":75}]", periods);
        Assert.Equal(periods, cached);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal("https://api.weather.gov/points/38.01234,-101.56789", handler.Requests[0].Uri);
        Assert.Equal("https://api.weather.gov/gridpoints/LZK/67,113/forecast", handler.Requests[1].Uri);
        Assert.All(handler.Requests, request =>
        {
            Assert.Contains("application/geo+json", request.Accept, StringComparison.Ordinal);
            Assert.Equal("NOC-IFC/2.0 (https://ops.example) (ops@example.test)", request.UserAgent);
        });
    }

    [Fact]
    public async Task DoesNotFollowAProviderReturnedForecastUrlOutsideNws()
    {
        var handler = new StubHandler(
        [
            """{"properties":{"forecast":"https://attacker.example/collect"}}""",
        ]);
        var client = new NwsForecastClient(new HttpClient(handler), new NwsForecastConfiguration("NOC-IFC/2.0 (https://ops.example)", ""));

        var periods = await client.GetForecastPeriodsJsonAsync(39.2134, -103.4567, CancellationToken.None);

        Assert.Null(periods);
        Assert.Single(handler.Requests);
    }

    private sealed class StubHandler(IReadOnlyList<string> responses) : HttpMessageHandler
    {
        public List<ForecastRequest> Requests { get; } = [];
        private int _responseIndex;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(new ForecastRequest(
                request.RequestUri!.ToString(),
                string.Join(",", request.Headers.Accept.Select(value => value.MediaType)),
                string.Join(" ", request.Headers.UserAgent)));
            var responseBody = responses[Math.Min(_responseIndex++, responses.Count - 1)];
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseBody, Encoding.UTF8, "application/geo+json"),
            });
        }
    }

    private sealed record ForecastRequest(string Uri, string Accept, string UserAgent);
}
