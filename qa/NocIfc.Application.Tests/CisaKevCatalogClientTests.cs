using System.Net;
using System.Text;
using NocIfc.Infrastructure.Integrations.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CisaKevCatalogClientTests
{
    [Fact]
    public async Task ReadsCisaFieldsAndSkipsEntriesWithoutCveIds()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """{"vulnerabilities":[{"cveID":"CVE-2026-1234","vendorProject":"Vendor","product":"Product","vulnerabilityName":"Vulnerability","dateAdded":"2026-11-20","shortDescription":"Description","requiredAction":"Patch now","dueDate":"2026-12-01"},{"cveID":""}]}""",
                Encoding.UTF8,
                "application/json"),
        });
        using var client = new HttpClient(handler);

        var entries = await new CisaKevCatalogClient(client).FetchAsync(CancellationToken.None);

        var entry = Assert.Single(entries);
        Assert.Equal("CVE-2026-1234", entry.CveId);
        Assert.Equal("Vendor", entry.Vendor);
        Assert.Equal("Product", entry.Product);
        Assert.Equal("Vulnerability", entry.VulnerabilityName);
        Assert.Equal("Description", entry.Description);
        Assert.Equal(new DateTime(2026, 11, 20), entry.DateAdded);
        Assert.Equal("NOC-IFC/2.0", handler.Request?.Headers.UserAgent.ToString());
        Assert.Equal("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", handler.Request?.RequestUri?.ToString());
    }

    [Fact]
    public async Task RejectsMalformedCatalogAndOversizedResponse()
    {
        using var malformedClient = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        }));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => new CisaKevCatalogClient(malformedClient).FetchAsync(CancellationToken.None));

        using var oversizedClient = new HttpClient(new StubHandler(_ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{}", Encoding.UTF8, "application/json"),
            };
            response.Content.Headers.ContentLength = 16 * 1024 * 1024 + 1;
            return response;
        }));
        await Assert.ThrowsAsync<InvalidDataException>(
            () => new CisaKevCatalogClient(oversizedClient).FetchAsync(CancellationToken.None));
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
