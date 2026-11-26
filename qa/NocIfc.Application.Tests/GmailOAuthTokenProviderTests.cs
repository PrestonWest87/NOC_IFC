using System.Net;
using System.Text;
using NocIfc.Infrastructure.Email;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class GmailOAuthTokenProviderTests
{
    [Fact]
    public async Task ExchangesRefreshCredentialsWithoutExposingThem()
    {
        var handler = new StubHandler(async request =>
        {
            Assert.Equal("https://oauth2.googleapis.com/token", request.RequestUri?.ToString());
            var form = await request.Content!.ReadAsStringAsync();
            Assert.Contains("client_id=client-id", form);
            Assert.Contains("client_secret=client-secret", form);
            Assert.Contains("refresh_token=refresh-token", form);
            return JsonResponse(HttpStatusCode.OK, "{\"access_token\":\"access-token\"}");
        });
        using var client = new HttpClient(handler);
        var provider = new GmailOAuthTokenProvider(client);

        var token = await provider.RefreshAsync(
            "client-id", "client-secret", "refresh-token", CancellationToken.None);

        Assert.Equal("access-token", token);
    }

    [Fact]
    public async Task MapsGoogleCredentialErrorsWithoutLeakingSecrets()
    {
        var handler = new StubHandler(_ => Task.FromResult(
            JsonResponse(HttpStatusCode.BadRequest, "{\"error\":\"invalid_grant\"}")));
        using var client = new HttpClient(handler);
        var provider = new GmailOAuthTokenProvider(client);

        var error = await Assert.ThrowsAsync<GmailOAuthException>(() => provider.RefreshAsync(
            "client-id", "do-not-log-this", "do-not-log-this-either", CancellationToken.None));

        Assert.Contains("Reauthorize", error.Message);
        Assert.DoesNotContain("do-not-log-this", error.Message);
    }

    private static HttpResponseMessage JsonResponse(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) => response(request);
    }
}
