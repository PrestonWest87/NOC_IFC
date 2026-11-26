using System.Net;
using System.Text;
using System.Text.Json;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Infrastructure.Integrations.Llm;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ProviderAwareLlmConnectionTesterTests
{
    [Fact]
    public async Task BuildsOpenAiCompatibleRequestWithBearerToken()
    {
        HttpRequestMessage? sent = null;
        var tester = Tester(request =>
        {
            sent = request;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"choices":[{"message":{"content":"CONNECTION_OK"}}]}""",
                    Encoding.UTF8,
                    "application/json"),
            };
        });

        var result = await tester.TestAsync(
            new LlmProviderSettings("openai_compatible", "https://8.8.8.8/v1", "key", "model-x"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains("CONNECTION_OK", result.Message, StringComparison.Ordinal);
        Assert.Equal("https://8.8.8.8/v1/chat/completions", sent?.RequestUri?.ToString());
        Assert.Equal("Bearer", sent?.Headers.Authorization?.Scheme);
        Assert.Equal("key", sent?.Headers.Authorization?.Parameter);
    }

    [Fact]
    public async Task UsesOllamaNativeProtocolAndAllowsExplicitLocalProviderLoopback()
    {
        string? requestJson = null;
        string? requestUri = null;
        var tester = Tester(async (request, cancellationToken) =>
        {
            requestUri = request.RequestUri?.ToString();
            requestJson = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"message":{"content":"native ok"}}""",
                    Encoding.UTF8,
                    "application/json"),
            };
        });

        var result = await tester.TestAsync(
            new LlmProviderSettings("ollama_native", "http://127.0.0.1:11434", "", "qwen3:8b"),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.EndsWith("/api/chat", requestUri, StringComparison.Ordinal);
        using var payload = JsonDocument.Parse(requestJson!);
        Assert.False(payload.RootElement.GetProperty("stream").GetBoolean());
        Assert.Equal(20, payload.RootElement.GetProperty("options").GetProperty("num_predict").GetInt32());
    }

    [Fact]
    public async Task RejectsPrivateEndpointForGenericProviderBeforeSending()
    {
        var calls = 0;
        var tester = Tester(_ =>
        {
            calls++;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            };
        });

        var result = await tester.TestAsync(
            new LlmProviderSettings("openai_compatible", "http://127.0.0.1:11434/v1", "", "model"),
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Contains("Endpoint is not allowed", result.Message, StringComparison.Ordinal);
        Assert.Equal(0, calls);
    }

    [Fact]
    public async Task GeneratesProviderAwareCompletionWithBoundedNativeOptions()
    {
        string? requestJson = null;
        var client = Tester(async (request, cancellationToken) =>
        {
            requestJson = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """{"message":{"content":"triage complete"}}""",
                    Encoding.UTF8,
                    "application/json"),
            };
        });

        var result = await client.CompleteAsync(
            new LlmProviderSettings("ollama_native", "http://127.0.0.1:11434", "", "qwen3:8b"),
            [new LlmChatMessage("user", "untrusted event")],
            0.2,
            4096,
            TimeSpan.FromMinutes(5),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("triage complete", result.Content);
        using var payload = JsonDocument.Parse(requestJson!);
        Assert.Equal(0.2, payload.RootElement.GetProperty("options").GetProperty("temperature").GetDouble());
        Assert.Equal(4096, payload.RootElement.GetProperty("options").GetProperty("num_predict").GetInt32());
        Assert.Equal("untrusted event", payload.RootElement.GetProperty("messages")[0].GetProperty("content").GetString());
    }

    private static ProviderAwareLlmClient Tester(
        Func<HttpRequestMessage, HttpResponseMessage> handler,
        bool allowPrivate = false) =>
        new(new HttpClient(new StubHandler((request, _) => Task.FromResult(handler(request)))), new LlmEndpointPolicy(allowPrivate));

    private static ProviderAwareLlmClient Tester(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler,
        bool allowPrivate = false) =>
        new(new HttpClient(new StubHandler(handler)), new LlmEndpointPolicy(allowPrivate));

    private sealed class StubHandler(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => handler(request, cancellationToken);
    }
}
