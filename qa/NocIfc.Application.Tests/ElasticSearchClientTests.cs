using System.Net;
using System.Text;
using System.Text.Json;
using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Integrations.Elastic;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ElasticSearchClientTests
{
    [Fact]
    public async Task ScrollsHighSeverityEventsMapsFieldsAndClearsTheScroll()
    {
        var handler = new StubHandler();
        var client = new ElasticSearchClient(handler);
        var events = await client.SearchHighSeverityAsync(
            new ElasticClientSettings("https://elastic.example.com", "encoded-api-key", true, "", 15, 1),
            DateTime.UtcNow.AddHours(-24),
            CancellationToken.None);

        Assert.Equal(2, events.Count);
        Assert.Equal("logs-a:doc-1", events[0].Id);
        Assert.Equal("ERROR", events[0].Severity);
        Assert.Equal("alert payload", events[0].Message);
        Assert.Equal("192.0.2.12", events[0].SourceIp);
        Assert.Equal("INTRUSION", events[0].EventCategory);
        Assert.Equal("doc-1", events[0].LegacyId);
        Assert.Equal("HIGH", events[1].Severity);
        Assert.Equal(250, events[1].Message?.Length);
        Assert.Equal(4, handler.Requests.Count);
        Assert.Contains("/_search?scroll=1m", handler.Requests[0].Uri, StringComparison.Ordinal);
        Assert.All(handler.Requests, request =>
        {
            Assert.Equal("ApiKey", request.AuthorizationScheme);
            Assert.Equal("encoded-api-key", request.AuthorizationParameter);
        });
        using var searchBody = JsonDocument.Parse(handler.Requests[0].Body!);
        Assert.Equal(1, searchBody.RootElement.GetProperty("size").GetInt32());
        Assert.Equal("scroll-3", JsonDocument.Parse(handler.Requests[^1].Body!).RootElement.GetProperty("scroll_id").GetString());
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private int _scrollRequests;
        public List<RequestInfo> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            Requests.Add(new RequestInfo(
                request.Method,
                request.RequestUri!.ToString(),
                body,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter));

            if (request.Method == HttpMethod.Delete)
            {
                return Response("""{"succeeded":true,"num_freed":1}""");
            }
            if (!request.RequestUri.AbsolutePath.EndsWith("_search/scroll", StringComparison.Ordinal))
            {
                return Response(SearchPage("scroll-1", Hit(
                    "doc-1", "logs-a", """{"@timestamp":"2026-11-26T18:00:00Z","log":{"level":"error","source":{"address":"192.0.2.12"}},"event":{"original":"alert payload","category":["intrusion"]},"message":""}""")));
            }

            if (++_scrollRequests == 1)
            {
                var source = "{\"@timestamp\":\"2026-11-26T17:00:00Z\",\"event\":{\"severity\":2.5,\"category\":\"malware\"},\"source\":{\"ip\":\"203.0.113.9\"},\"message\":\""
                    + new string('x', 300) + "\"}";
                return Response(SearchPage("scroll-2", Hit("doc-2", "logs-b", source)));
            }
            return Response("""{"_scroll_id":"scroll-3","hits":{"hits":[]}}""");
        }

        private static string SearchPage(string scrollId, string hit) =>
            "{\"_scroll_id\":\"" + scrollId + "\",\"hits\":{\"hits\":[" + hit + "]}}";

        private static string Hit(string id, string index, string source) =>
            "{\"_id\":\"" + id + "\",\"_index\":\"" + index + "\",\"_source\":" + source + "}";

        private static HttpResponseMessage Response(string body) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
    }

    private sealed record RequestInfo(
        HttpMethod Method,
        string Uri,
        string? Body,
        string? AuthorizationScheme,
        string? AuthorizationParameter);
}
