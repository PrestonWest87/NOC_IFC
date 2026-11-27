using System.Net;
using System.Text;
using NocIfc.Infrastructure.Integrations.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RssFeedClientTests
{
    [Fact]
    public async Task DownloadsFeedWithExpectedHeaders()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("<rss />", Encoding.UTF8, "application/xml"),
        });
        using var client = new HttpClient(handler);

        var result = await new RssFeedClient(client).FetchAsync("https://feeds.example.test/rss", CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("<rss />", Encoding.UTF8.GetString(result));
        Assert.Equal("https://feeds.example.test/rss", handler.Request?.RequestUri?.ToString());
        Assert.Contains("Chrome/120.0.0.0", handler.Request?.Headers.UserAgent.ToString());
        Assert.Contains("en-US", handler.Request?.Headers.AcceptLanguage.ToString());
        Assert.Contains("q=0.5", handler.Request?.Headers.AcceptLanguage.ToString());
    }

    [Fact]
    public async Task SkipsHttpErrorsAndOversizedFeedBodies()
    {
        var responseIndex = 0;
        var handler = new StubHandler(_ =>
        {
            responseIndex++;
            if (responseIndex == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            }
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("too big", Encoding.UTF8, "application/xml"),
            };
            response.Content.Headers.ContentLength = 8 * 1024 * 1024 + 1;
            return response;
        });
        using var client = new HttpClient(handler);
        var feedClient = new RssFeedClient(client);

        Assert.Null(await feedClient.FetchAsync("https://feeds.example.test/error", CancellationToken.None));
        Assert.Null(await feedClient.FetchAsync("https://feeds.example.test/large", CancellationToken.None));
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(respond(request));
        }
    }
}
