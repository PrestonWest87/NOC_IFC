using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;
using NocIfc.Domain.Regional;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalDataQueriesTests
{
    [Fact]
    public async Task SelectsLayersFiltersCurrentAlertsAndKeepsViewportIntersections()
    {
        var now = DateTime.UtcNow;
        var source = new StubRegionalDataStore
        {
            Layers = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["nws_ar"] = FeatureCollection(
                    Feature("crossing", Polygon((-95, 34), (-91, 34), (-91, 36), (-95, 36), (-95, 34)), now.AddHours(1), now.AddHours(-1)),
                    Feature("inside", Point(-93, 34), now.AddHours(1), now.AddHours(-1)),
                    Feature("expired", Point(-93, 34), now.AddMinutes(-1), now.AddHours(-1)),
                    Feature("future", Point(-93, 34), now.AddHours(1), now.AddHours(1)),
                    Feature("cancel", Point(-93, 34), now.AddHours(1), now.AddHours(-1), "Cancel"),
                    Feature("outside", Point(-80, 40), now.AddHours(1), now.AddHours(-1)),
                    Feature("unknown-geometry", new JsonObject { ["type"] = "Circle", ["coordinates"] = PointCoordinates(0, 0) }, now.AddHours(1), now.AddHours(-1))),
                ["spc_day1"] = FeatureCollection(Feature("spc-inside", Point(-93, 34), null, null)),
            },
            Statuses = new Dictionary<string, GeoJsonFeedStatus>(StringComparer.Ordinal)
            {
                ["nws_region"] = new(
                    "nws_region", now.AddMinutes(-2), now.AddMinutes(-1), now.AddMinutes(-2),
                    "upstream timeout", 503, 42, null, 8, "{\"arkansas_alert_count\":3}"),
            },
            EventTypes = ["Tornado Warning", "Winter Storm Warning"],
        };
        var queries = new RegionalDataQueries(source);

        var result = await queries.GetGeoJsonAsync(" nws_ar, spc_day1 ", "-94,33,-92,35", CancellationToken.None);

        Assert.Equal(new[] { "nws_ar", "spc_day1" }, source.RequestedLayers);
        var nwsFeatures = Assert.IsType<JsonArray>(Assert.IsType<JsonObject>(result["nws_ar"])["features"]);
        Assert.Equal(new[] { "crossing", "inside", "unknown-geometry" }, nwsFeatures
            .Select(feature => feature!["id"]!.GetValue<string>()));
        var spcFeatures = Assert.IsType<JsonArray>(Assert.IsType<JsonObject>(result["spc_day1"])["features"]);
        Assert.Single(spcFeatures);
        Assert.Equal(new[] { "Tornado Warning", "Winter Storm Warning" },
            Assert.IsType<JsonArray>(result["nws_events"]).Select(item => item!.GetValue<string>()));
        var meta = Assert.IsType<JsonObject>(result["meta"]);
        Assert.Equal("nws_ar", meta["nws_ar"]!["layer"]!.GetValue<string>());
        Assert.Equal("stale", meta["nws_ar"]!["status"]!.GetValue<string>());
        Assert.Equal(503, meta["nws_ar"]!["last_http_status"]!.GetValue<int>());
        Assert.Equal(3, meta["nws_ar"]!["coverage"]!["arkansas_alert_count"]!.GetValue<int>());
        Assert.Equal("missing", meta["spc_day1"]!["status"]!.GetValue<string>());
        Assert.False(string.IsNullOrWhiteSpace(meta["server_time"]!.GetValue<string>()));
    }

    [Fact]
    public async Task SummaryAndInvalidLayerOrViewportFollowRouteContract()
    {
        var queries = new RegionalDataQueries(new StubRegionalDataStore());
        var summary = await queries.GetGeoJsonAsync("summary", null, CancellationToken.None);
        Assert.DoesNotContain(((JsonObject)summary).Select(property => property.Key),
            key => key is not ("nws_events" or "meta"));
        await Assert.ThrowsAsync<ArgumentException>(() => queries.GetGeoJsonAsync("invalid", null, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => queries.GetGeoJsonAsync("spc_day1", "-91,35,-92,34", CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => queries.GetGeoJsonAsync("spc_day1", "-91,35,NaN,34", CancellationToken.None));
    }

    [Fact]
    public async Task BuildsWeatherAlertLogFromCurrentNwsAlertsAndSignificantEarthquakes()
    {
        var now = DateTime.UtcNow;
        var nws = new JsonObject
        {
            ["type"] = "Feature",
            ["id"] = "feature-id",
            ["properties"] = new JsonObject
            {
                ["id"] = "cap-alert-id",
                ["event"] = "Tornado Warning",
                ["severity"] = "Extreme",
                ["certainty"] = "Observed",
                ["headline"] = "Tornado near town",
                ["areaDesc"] = "County A",
                ["sent"] = now.ToString("O"),
                ["effective"] = now.AddMinutes(-5).ToString("O"),
                ["expires"] = now.AddMinutes(30).ToString("O"),
                ["ends"] = "",
                ["eventEndingTime"] = now.AddMinutes(20).ToString("O"),
                ["messageType"] = "Alert",
                ["noc_coverage_precision"] = "county_geocode",
                ["description"] = "Observed tornado.",
                ["instruction"] = "Take shelter.",
            },
            ["geometry"] = null,
        };
        var quakeTime = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeMilliseconds();
        var earthquake = new JsonObject
        {
            ["type"] = "Feature",
            ["id"] = "usgs-1",
            ["properties"] = new JsonObject { ["mag"] = 2.5, ["place"] = "Near Conway", ["time"] = quakeTime },
            ["geometry"] = new JsonObject
            {
                ["type"] = "Point",
                ["coordinates"] = new JsonArray(JsonValue.Create(-92.4), JsonValue.Create(35.1), JsonValue.Create(6.2)),
            },
        };
        var smallEarthquake = new JsonObject
        {
            ["type"] = "Feature",
            ["id"] = "usgs-small",
            ["properties"] = new JsonObject { ["mag"] = 1.9, ["place"] = "Small", ["time"] = quakeTime },
            ["geometry"] = new JsonObject { ["type"] = "Point", ["coordinates"] = new JsonArray(0, 0, 1) },
        };
        var store = new StubRegionalDataStore
        {
            Layers = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["nws_ar"] = FeatureCollection(nws),
                ["usgs_ar"] = FeatureCollection(earthquake),
                ["usgs_oos"] = FeatureCollection(smallEarthquake),
            },
        };

        var result = await new RegionalDataQueries(store).GetWeatherAlertsLogAsync(CancellationToken.None);

        Assert.Equal(2, result.Count);
        Assert.Equal("[AR] Tornado Warning", result[0]!["Event"]!.GetValue<string>());
        Assert.Equal("cap-alert-id", result[0]!["Alert ID"]!.GetValue<string>());
        Assert.Equal(now.AddMinutes(20).ToString("O"), result[0]!["Expected End"]!.GetValue<string>());
        Assert.Equal("[USGS AR] Earthquake", result[1]!["Event"]!.GetValue<string>());
        Assert.Equal("Minor", result[1]!["Severity"]!.GetValue<string>());
        Assert.Contains("Near Conway", result[1]!["Description"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    private static string FeatureCollection(params JsonObject[] features)
    {
        var collection = new JsonObject
        {
            ["type"] = "FeatureCollection",
            ["features"] = new JsonArray(features.Select(feature => (JsonNode?)feature).ToArray()),
        };
        return collection.ToJsonString();
    }

    private static JsonObject Feature(
        string id,
        JsonObject? geometry,
        DateTime? expires,
        DateTime? effective,
        string? messageType = "Alert") => new()
    {
        ["type"] = "Feature",
        ["id"] = id,
        ["properties"] = new JsonObject
        {
            ["messageType"] = messageType,
            ["expires"] = expires?.ToString("O"),
            ["effective"] = effective?.ToString("O"),
        },
        ["geometry"] = geometry,
    };

    private static JsonObject Point(double longitude, double latitude) => new()
    {
        ["type"] = "Point",
        ["coordinates"] = PointCoordinates(longitude, latitude),
    };

    private static JsonArray PointCoordinates(double longitude, double latitude) =>
        new(JsonValue.Create(longitude), JsonValue.Create(latitude));

    private static JsonObject Polygon(params (double Longitude, double Latitude)[] ring) => new()
    {
        ["type"] = "Polygon",
        ["coordinates"] = new JsonArray(new JsonArray(ring.Select(point =>
            (JsonNode?)PointCoordinates(point.Longitude, point.Latitude)).ToArray())),
    };

    private sealed class StubRegionalDataStore : IRegionalDataStore
    {
        public IReadOnlyDictionary<string, string?> Layers { get; init; } = new Dictionary<string, string?>();
        public IReadOnlyDictionary<string, GeoJsonFeedStatus> Statuses { get; init; } = new Dictionary<string, GeoJsonFeedStatus>();
        public IReadOnlyList<string> EventTypes { get; init; } = [];
        public IReadOnlyList<string> RequestedLayers { get; private set; } = [];

        public Task<IReadOnlyDictionary<string, string?>> GetGeoJsonLayersAsync(
            IReadOnlyList<string> feedNames,
            CancellationToken cancellationToken)
        {
            RequestedLayers = feedNames;
            return Task.FromResult(Layers);
        }

        public Task<IReadOnlyDictionary<string, GeoJsonFeedStatus>> GetGeoJsonFeedStatusesAsync(
            IReadOnlyList<string> feedNames,
            CancellationToken cancellationToken) => Task.FromResult(Statuses);

        public Task<IReadOnlyList<string>> GetActiveNwsEventTypesAsync(
            DateTime nowUtc,
            CancellationToken cancellationToken) => Task.FromResult(EventTypes);
    }
}
