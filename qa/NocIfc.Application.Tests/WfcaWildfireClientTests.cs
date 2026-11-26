using System.Net;
using System.Text;
using System.Text.Json;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Integrations.Weather;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class WfcaWildfireClientTests
{
    [Fact]
    public async Task FiltersCorridorIncidentsJoinsWfsLayersAndCachesTheSnapshot()
    {
        var handler = new WfsHandler();
        var client = Client(handler, [Site(-92.3, 34.75)]);

        var json = await client.GetActiveWildfiresJsonAsync(CancellationToken.None);
        var cachedJson = await client.GetActiveWildfiresJsonAsync(CancellationToken.None);

        Assert.Equal(json, cachedJson);
        Assert.Equal(3, handler.Requests.Count);
        using var payload = JsonDocument.Parse(json);
        var root = payload.RootElement;
        var incidents = root.GetProperty("incidents");
        Assert.Equal(2, incidents.GetArrayLength());
        Assert.Contains(incidents.EnumerateArray(), fire => fire.GetProperty("name").GetString() == "Large Fire");
        Assert.Contains(incidents.EnumerateArray(), fire => fire.GetProperty("name").GetString() == "Small Nearby");
        Assert.DoesNotContain(incidents.EnumerateArray(), fire => fire.GetProperty("name").GetString() == "Small Distant");
        Assert.DoesNotContain(incidents.EnumerateArray(), fire => fire.GetProperty("name").GetString() == "Outside Region");
        Assert.Single(root.GetProperty("perimeters").EnumerateArray());
        Assert.Single(root.GetProperty("footprints").EnumerateArray());
        Assert.Equal("ok", root.GetProperty("meta").GetProperty("status").GetString());
        Assert.Equal(50, root.GetProperty("meta").GetProperty("coverage_miles").GetInt32());
        Assert.All(handler.Requests, uri => Assert.Contains("bbox=", uri, StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReturnsAnErrorSnapshotWhenTheFirstWfsRequestFails()
    {
        var handler = new WfsHandler(fail: true);
        var client = Client(handler, []);

        var json = await client.GetActiveWildfiresJsonAsync(CancellationToken.None);

        using var payload = JsonDocument.Parse(json);
        Assert.Equal("error", payload.RootElement.GetProperty("meta").GetProperty("status").GetString());
        Assert.Empty(payload.RootElement.GetProperty("incidents").EnumerateArray());
        Assert.Contains("HTTP 503", payload.RootElement.GetProperty("meta").GetProperty("last_error").GetString());
        Assert.Single(handler.Requests);
    }

    private static WfcaWildfireClient Client(WfsHandler handler, IReadOnlyList<MonitoredLocationEntry> sites) =>
        new(new HttpClient(handler), new StubFacilityStore(sites), ArkansasFireCoverage.LoadBundled(), new WfcaWildfireSnapshotCache());

    private static MonitoredLocationEntry Site(double longitude, double latitude) => new(
        1, "NOC", latitude, longitude, "NOC", "Central", "P1-Critical", null, null,
        false, null, null, null, null, null, null, null, null);

    private static object Incident(
        string name,
        string irwinId,
        double longitude,
        double latitude,
        double acres,
        double contained = 0,
        string? stale = null) => new
    {
        type = "Feature",
        properties = new Dictionary<string, object?>
        {
            ["incidenttypecategory"] = "WF",
            ["stale_flag"] = stale,
            ["percentcontained"] = contained,
            ["wfca_reportedacres"] = acres,
            ["incidentname"] = name,
            ["irwinid"] = irwinId,
            ["uniquefireidentifier"] = $"US-AR-{irwinId}",
            ["poostate"] = "US-AR",
            ["poocounty"] = "Pulaski",
            ["firediscoverydatetime"] = "2026-11-26T12:00:00Z",
            ["modifiedondatetime_dt"] = "2026-11-26T13:00:00Z",
            ["firecause"] = "Unknown",
        },
        geometry = new { type = "Point", coordinates = new[] { longitude, latitude } },
    };

    private static object Perimeter(string irwinId) => new
    {
        type = "Feature",
        properties = new { attr_irwinid = irwinId, poly_datecurrent = "2026-11-26T14:00:00Z" },
        geometry = new
        {
            type = "Polygon",
            coordinates = new[]
            {
                new[] { new[] { -92.31, 34.74 }, new[] { -92.29, 34.74 }, new[] { -92.29, 34.76 }, new[] { -92.31, 34.76 }, new[] { -92.31, 34.74 } },
            },
        },
    };

    private static object Footprint(string irwinId) => new
    {
        type = "Feature",
        properties = new
        {
            irwinid = irwinId,
            age_bucket = "recent",
            hours_since = 4,
            area_acres = 0.8,
            detection_count = 2,
            sensor = "VIIRS",
            latest_acq_epoch = 1_795_693_200,
            wfca_timestamp = "2026-11-26T14:00:00Z",
        },
        geometry = new
        {
            type = "Polygon",
            coordinates = new[]
            {
                new[] { new[] { -92.3005, 34.7495 }, new[] { -92.2995, 34.7495 }, new[] { -92.2995, 34.7505 }, new[] { -92.3005, 34.7505 }, new[] { -92.3005, 34.7495 } },
            },
        },
    };

    private sealed class WfsHandler(bool fail = false) : HttpMessageHandler
    {
        public List<string> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var requestUri = request.RequestUri!.ToString();
            Requests.Add(requestUri);
            if (fail)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }
            var decodedQuery = Uri.UnescapeDataString(request.RequestUri.Query);
            object[] features;
            if (decodedQuery.Contains("WFCA:WFIGS_Incidents", StringComparison.Ordinal))
            {
                features =
                [
                    Incident("Large Fire", "big-id", -92.30, 34.75, 5),
                    Incident("Small Nearby", "small-near", -92.30, 34.75, 0.5),
                    Incident("Small Distant", "small-far", -92.10, 35.10, 0.5),
                    Incident("Outside Region", "outside", -80, 40, 8),
                    Incident("Contained", "contained", -92.30, 34.75, 8, contained: 100),
                    Incident("Stale", "stale", -92.30, 34.75, 8, stale: "true"),
                ];
            }
            else if (decodedQuery.Contains("WFCA:WFIGS_Perimeters", StringComparison.Ordinal))
            {
                features = [Perimeter("{BIG-ID}")];
            }
            else if (decodedQuery.Contains("WFCA:FIRMS_Footprints", StringComparison.Ordinal))
            {
                features = [Footprint("small-near"), Footprint("small-far")];
            }
            else
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest));
            }
            var body = JsonSerializer.Serialize(new { type = "FeatureCollection", numberMatched = features.Length, features });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class StubFacilityStore(IReadOnlyList<MonitoredLocationEntry> sites) : IFacilityDirectoryStore
    {
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(sites);
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(sites);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>([]);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
            int locationId,
            IReadOnlyList<MonitoredLocationContactValue> contacts,
            CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>([]);
        public Task<int> ImportLocationsAsync(
            IReadOnlyList<MonitoredLocationImportRow> locations,
            string mode,
            CancellationToken cancellationToken) => Task.FromResult(0);
        public Task UpdateLocationsAsync(
            IReadOnlyList<MonitoredLocationEditRow> locations,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
