using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;
using NocIfc.Domain.Regional;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalMapQueriesTests
{
    [Fact]
    public async Task CompilesCachedHazardsIntoSixPositionResponseAndScopesSites()
    {
        var now = DateTime.UtcNow;
        var polygon = Polygon((-94, 34), (-92, 34), (-92, 36), (-94, 36), (-94, 34));
        var store = new StubRegionalDataStore
        {
            Layers = new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["spc_day1"] = Collection(Feature("spc", (JsonObject)polygon.DeepClone(), new JsonObject { ["LABEL"] = "HIGH" })),
                ["nws_ar"] = Collection(
                    Feature("warning", (JsonObject)polygon.DeepClone(), AlertProperties("Tornado Warning", now.AddHours(1), now.AddHours(-1))),
                    Feature("expired", (JsonObject)polygon.DeepClone(), AlertProperties("Severe Thunderstorm Warning", now.AddMinutes(-1), now.AddHours(-1)))),
                ["nws_oos"] = Collection(Feature("oos", (JsonObject)polygon.DeepClone(), AlertProperties("Winter Storm Watch", now.AddHours(1), now.AddHours(-1)))),
                ["usgs_ar"] = Collection(Earthquake(-93, 35, 4.2)),
                ["usgs_oos"] = Collection(),
            },
        };
        var wildfireProvider = new StubWildfireProvider("""
            {"incidents":[{"name":"Nearby Fire","lon":-93,"lat":35,"acres":5}],"perimeters":[],"footprints":[]}
            """);
        var queries = Queries(store, wildfireProvider);
        var request = new JsonObject
        {
            ["toggles"] = new JsonObject
            {
                ["spc"] = true, ["warn"] = true, ["watch"] = true, ["oos"] = false,
                ["earthquakes"] = true, ["active_wildfires"] = true,
            },
            ["selected_events"] = new JsonArray("Tornado Warning", "Winter Storm Watch"),
            ["include_analytics"] = true,
            ["map_df"] = new JsonArray(
                Site("Allowed", 0, 0),
                Site("Not Allowed", -93, 35)),
        };

        var result = await queries.CompileAsync(
            request, [Location(1, "Allowed", -93, 35)], CancellationToken.None);

        Assert.Equal(6, result.Count);
        var processed = Assert.IsType<JsonObject>(result[0]);
        Assert.Single(Assert.IsType<JsonArray>(processed["ar_warn"]!["features"]));
        Assert.Single(Assert.IsType<JsonArray>(processed["oos_watch"]!["features"]));
        var sites = Assert.IsType<JsonArray>(result[4]);
        Assert.All(sites, site => Assert.Equal("Allowed", site!["Monitored Site"]!.GetValue<string>()));
        var hazards = sites.Select(site => site!["Hazard"]!.GetValue<string>()).ToArray();
        Assert.Contains("SPC: HIGH", hazards);
        Assert.Contains("[AR] Tornado Warning", hazards);
        Assert.Contains("[OOS] Winter Storm Watch", hazards);
        Assert.Contains("Active Wildfire: Nearby Fire", hazards);
        Assert.Contains("EQ (AR): M4.2", hazards);
        var analytics = Assert.IsType<JsonObject>(result[5]);
        Assert.Equal(1, analytics["total_sites"]!.GetValue<int>());
        Assert.Equal(1, analytics["at_risk_sites"]!.GetValue<int>());
        Assert.Equal("HIGH", analytics["highest_risk"]!.GetValue<string>());
    }

    [Fact]
    public async Task ReconstructsCountyAlertsAndReportsUnresolvedZones()
    {
        var countyGeometry = Polygon((-94, 34), (-92, 34), (-92, 36), (-94, 36), (-94, 34));
        var countyProvider = new StubCountyGeometryProvider(new Dictionary<string, RegionalCountyGeometry>(StringComparer.Ordinal)
        {
            ["05001"] = new("05001", "05", countyGeometry.DeepClone()),
        });
        var alertProperties = AlertProperties("Tornado Warning", null, null);
        alertProperties["geocode"] = new JsonObject { ["SAME"] = new JsonArray("005001") };
        var unresolvedProperties = AlertProperties("Tornado Warning", null, null);
        unresolvedProperties["areaDesc"] = "Unknown county zone";
        var store = new StubRegionalDataStore();
        var queries = Queries(store, new StubWildfireProvider("{}"), countyProvider);
        var request = new JsonObject
        {
            ["ar_data"] = JsonNode.Parse(Collection(
                Feature("county-alert", null, alertProperties),
                Feature("zone-alert", null, unresolvedProperties))),
            ["selected_events"] = new JsonArray("Tornado Warning"),
            ["map_df"] = new JsonArray(Site("NOC", -93, 35)),
        };

        var result = await queries.CompileAsync(
            request,
            [Location(1, "NOC", -93, 35)],
            CancellationToken.None);

        var processed = Assert.IsType<JsonObject>(result[0]);
        var warningFeatures = Assert.IsType<JsonArray>(processed["ar_warn"]!["features"]);
        Assert.True(warningFeatures.Count == 1, result.ToJsonString());
        Assert.Equal(countyGeometry.ToJsonString(), warningFeatures[0]!["geometry"]!.ToJsonString());
        Assert.Contains(Assert.IsType<JsonArray>(result[2]), message =>
            message!.GetValue<string>().Contains("area=Unknown county zone", StringComparison.Ordinal));
        Assert.Single(Assert.IsType<JsonArray>(result[4]));
    }

    [Fact]
    public async Task RejectsInvalidViewportBounds()
    {
        var queries = Queries(new StubRegionalDataStore(), new StubWildfireProvider("{}"));
        await Assert.ThrowsAsync<ArgumentException>(() => queries.CompileAsync(
            new JsonObject { ["viewport_bounds"] = new JsonArray(-91, 35, -92, 34) },
            [Location(1, "NOC", -93, 35)],
            CancellationToken.None));
    }

    [Fact]
    public async Task RefreshesCompiledMatrixWhenCachedFeedRevisionChanges()
    {
        var now = DateTime.UtcNow;
        var store = new StubRegionalDataStore
        {
            Layers = new Dictionary<string, string?>(StringComparer.Ordinal) { ["nws_ar"] = Collection() },
            Statuses = FeedStatuses(now, featureCount: 0),
        };
        var queries = Queries(store, new StubWildfireProvider("{}"));
        var request = new JsonObject
        {
            ["toggles"] = new JsonObject { ["spc"] = false, ["warn"] = true, ["watch"] = false, ["oos"] = false, ["earthquakes"] = false },
            ["selected_events"] = new JsonArray("Tornado Warning"),
            ["map_df"] = new JsonArray(Site("Cache NOC", -93, 35)),
        };
        var locations = new[] { Location(7, "Cache NOC", -93, 35) };

        var initial = await queries.CompileAsync(request, locations, CancellationToken.None);
        Assert.Empty(Assert.IsType<JsonArray>(initial[4]));

        var alert = Feature("alert", Polygon((-94, 34), (-92, 34), (-92, 36), (-94, 36), (-94, 34)),
            AlertProperties("Tornado Warning", now.AddHours(1), now.AddHours(-1)));
        store.Layers = new Dictionary<string, string?>(StringComparer.Ordinal) { ["nws_ar"] = Collection(alert) };
        store.Statuses = FeedStatuses(now.AddSeconds(1), featureCount: 1);

        var refreshed = await queries.CompileAsync(request, locations, CancellationToken.None);
        Assert.Single(Assert.IsType<JsonArray>(refreshed[4]));
    }

    [Fact]
    public void PointCoverageHonorsPolygonHolesAndEdges()
    {
        var polygon = new JsonObject
        {
            ["type"] = "Polygon",
            ["coordinates"] = new JsonArray(
                Ring((-94, 34), (-92, 34), (-92, 36), (-94, 36), (-94, 34)),
                Ring((-93.5, 34.5), (-92.5, 34.5), (-92.5, 35.5), (-93.5, 35.5), (-93.5, 34.5))),
        };

        Assert.True(RegionalGeoJsonViewportFilter.CoversPoint(polygon, -94, 35));
        Assert.False(RegionalGeoJsonViewportFilter.CoversPoint(polygon, -93, 35));
    }

    private static RegionalMapQueries Queries(
        StubRegionalDataStore store,
        StubWildfireProvider wildfireProvider,
        StubCountyGeometryProvider? countyProvider = null) =>
        new(
            new RegionalDataQueries(store),
            new RegionalWildfireQueries(wildfireProvider),
            countyProvider ?? new StubCountyGeometryProvider(new Dictionary<string, RegionalCountyGeometry>()));

    private static JsonObject Site(string name, double longitude, double latitude) => new()
    {
        ["Name"] = name,
        ["Type"] = "NOC",
        ["District"] = "Central",
        ["Priority"] = "P1-Critical",
        ["Lon"] = longitude,
        ["Lat"] = latitude,
    };

    private static MonitoredLocationEntry Location(int id, string name, double longitude, double latitude) => new(
        id, name, latitude, longitude, "NOC", "Central", "P1-Critical", null, null,
        false, null, null, null, null, null, null, null, null);

    private static JsonObject AlertProperties(string eventName, DateTime? expires, DateTime? effective) => new()
    {
        ["event"] = eventName,
        ["headline"] = eventName,
        ["severity"] = "Extreme",
        ["messageType"] = "Alert",
        ["expires"] = expires?.ToString("O"),
        ["effective"] = effective?.ToString("O"),
    };

    private static JsonObject Earthquake(double longitude, double latitude, double magnitude) => new()
    {
        ["type"] = "Feature",
        ["properties"] = new JsonObject { ["mag"] = magnitude, ["place"] = "Test" },
        ["geometry"] = new JsonObject
        {
            ["type"] = "Point",
            ["coordinates"] = new JsonArray(longitude, latitude, 5),
        },
    };

    private static JsonObject Feature(string id, JsonObject? geometry, JsonObject properties) => new()
    {
        ["type"] = "Feature",
        ["id"] = id,
        ["properties"] = properties,
        ["geometry"] = geometry,
    };

    private static JsonObject Polygon(params (double Longitude, double Latitude)[] points) => new()
    {
        ["type"] = "Polygon",
        ["coordinates"] = new JsonArray(Ring(points)),
    };

    private static JsonArray Ring(params (double Longitude, double Latitude)[] points) =>
        new(points.Select(point => (JsonNode?)new JsonArray(point.Longitude, point.Latitude)).ToArray());

    private static string Collection(params JsonObject[] features) => new JsonObject
    {
        ["type"] = "FeatureCollection",
        ["features"] = new JsonArray(features.Select(feature => (JsonNode?)feature).ToArray()),
    }.ToJsonString();

    private sealed class StubRegionalDataStore : IRegionalDataStore
    {
        public IReadOnlyDictionary<string, string?> Layers { get; set; } = new Dictionary<string, string?>();
        public IReadOnlyDictionary<string, GeoJsonFeedStatus> Statuses { get; set; } = new Dictionary<string, GeoJsonFeedStatus>();

        public Task<IReadOnlyDictionary<string, string?>> GetGeoJsonLayersAsync(
            IReadOnlyList<string> feedNames,
            CancellationToken cancellationToken) => Task.FromResult(
                (IReadOnlyDictionary<string, string?>)feedNames
                    .Where(Layers.ContainsKey)
                    .ToDictionary(name => name, name => Layers[name], StringComparer.Ordinal));

        public Task<IReadOnlyDictionary<string, GeoJsonFeedStatus>> GetGeoJsonFeedStatusesAsync(
            IReadOnlyList<string> feedNames,
            CancellationToken cancellationToken) => Task.FromResult(Statuses);

        public Task<IReadOnlyList<string>> GetActiveNwsEventTypesAsync(
            DateTime nowUtc,
            CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>([]);
    }

    private sealed class StubWildfireProvider(string json) : IRegionalWildfireProvider
    {
        public Task<string> GetActiveWildfiresJsonAsync(CancellationToken cancellationToken) => Task.FromResult(json);
    }

    private sealed class StubCountyGeometryProvider(
        IReadOnlyDictionary<string, RegionalCountyGeometry> counties) : IRegionalCountyGeometryProvider
    {
        public IReadOnlyDictionary<string, RegionalCountyGeometry> GetRegionalCounties() => counties;
    }

    private static IReadOnlyDictionary<string, GeoJsonFeedStatus> FeedStatuses(DateTime updatedAt, int featureCount) =>
        new Dictionary<string, GeoJsonFeedStatus>(StringComparer.Ordinal)
        {
            ["nws_region"] = new("nws_region", updatedAt, updatedAt, updatedAt, null, 200, 10, null, featureCount, null),
        };
}
