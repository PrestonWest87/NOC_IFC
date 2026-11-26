using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.Regional;

public sealed class RegionalMapQueries(
    RegionalDataQueries regionalData,
    RegionalWildfireQueries wildfires,
    IRegionalCountyGeometryProvider countyGeometry)
{
    private static readonly string[] LegacyFeedFields =
        ["spc_data", "ar_data", "oos_data", "usgs_ar_data", "usgs_oos_data"];
    private static readonly string[] StateFipsCodes =
        ["AR:05", "LA:22", "TX:48", "MS:28", "MO:29", "OK:40", "TN:47"];
    private static readonly string[] FireRiskEventTerms = ["Fire Weather", "Red Flag", "Fire Warning", "Extreme Fire"];
    private static readonly HashSet<string> BorderStateFips = ["22", "48", "28", "29", "40", "47"];
    private static readonly object MapCacheLock = new();
    private static readonly Dictionary<string, MapCacheEntry> MapCache = new(StringComparer.Ordinal);

    public async Task<JsonArray> CompileAsync(
        JsonObject? request,
        IReadOnlyList<MonitoredLocationEntry> authorizedLocations,
        CancellationToken cancellationToken)
    {
        request ??= new JsonObject();
        var toggles = request["toggles"] as JsonObject;
        var includeAnalytics = ReadBoolean(request["include_analytics"]);
        var viewport = ParseViewport(request["viewport_bounds"]);
        var scopedViewport = includeAnalytics ? null : viewport;
        var viewportText = scopedViewport is { } bounds ? FormatViewport(bounds) : null;
        var mapRows = SelectAuthorizedMapRows(request["map_df"], authorizedLocations);
        if (scopedViewport is { } siteViewport)
        {
            mapRows = mapRows.Where(row => SiteIsInViewport(row, siteViewport)).ToList();
        }

        var selectedEvents = (request["selected_events"] as JsonArray ?? [])
            .Select(ToPythonString)
            .ToHashSet(StringComparer.Ordinal);
        var hasLegacySnapshot = LegacyFeedFields.Any(name =>
            request.TryGetPropertyValue(name, out var value) && value is not null);

        JsonNode? spcData;
        JsonNode? arData;
        JsonNode? oosData;
        JsonNode? usgsArData;
        JsonNode? usgsOosData;
        JsonNode? feedMetadata = null;
        if (hasLegacySnapshot)
        {
            spcData = CloneProperty(request, "spc_data");
            arData = CloneProperty(request, "ar_data");
            oosData = CloneProperty(request, "oos_data");
            usgsArData = CloneProperty(request, "usgs_ar_data");
            usgsOosData = CloneProperty(request, "usgs_oos_data");
            if (scopedViewport is { } legacyViewport)
            {
                spcData = RegionalGeoJsonViewportFilter.FilterToViewport(spcData, legacyViewport);
                arData = RegionalGeoJsonViewportFilter.FilterToViewport(
                    FilterCurrentLegacyAlerts(arData), legacyViewport);
                oosData = RegionalGeoJsonViewportFilter.FilterToViewport(
                    FilterCurrentLegacyAlerts(oosData), legacyViewport);
                usgsArData = RegionalGeoJsonViewportFilter.FilterToViewport(usgsArData, legacyViewport);
                usgsOosData = RegionalGeoJsonViewportFilter.FilterToViewport(usgsOosData, legacyViewport);
            }
            else
            {
                arData = FilterCurrentLegacyAlerts(arData);
                oosData = FilterCurrentLegacyAlerts(oosData);
            }
        }
        else
        {
            var requestedFeeds = RequestedFeeds(toggles, includeAnalytics);
            var feeds = await regionalData.GetGeoJsonAsync(
                string.Join(',', requestedFeeds), viewportText, cancellationToken);
            feedMetadata = CloneProperty(feeds, "meta");
            spcData = CloneProperty(feeds, "spc_day1");
            arData = CloneProperty(feeds, "nws_ar");
            oosData = CloneProperty(feeds, "nws_oos");
            usgsArData = CloneProperty(feeds, "usgs_ar");
            usgsOosData = CloneProperty(feeds, "usgs_oos");
        }

        var includeWildfires = includeAnalytics || ReadBoolean(GetToggle(toggles, "active_wildfires", false));
        JsonNode? wildfireData = includeWildfires
            ? await wildfires.GetAsync(viewportText, cancellationToken)
            : null;
        var cacheKey = hasLegacySnapshot
            ? null
            : BuildCacheKey(toggles, selectedEvents, includeAnalytics, viewportText, mapRows, feedMetadata, arData, oosData, wildfireData);
        if (cacheKey is not null && TryGetCachedMap(cacheKey) is { } cached)
        {
            return cached;
        }

        var counties = countyGeometry.GetRegionalCounties();
        var arNws = ProcessNwsAlerts(arData, "AR", isOutOfState: false, selectedEvents, counties);
        var oosNws = ProcessNwsAlerts(oosData, "OOS", isOutOfState: true, selectedEvents, counties);
        var diagnostics = new JsonArray();
        foreach (var message in arNws.Diagnostics.Concat(oosNws.Diagnostics))
        {
            diagnostics.Add(message);
        }
        foreach (var alert in arNws.ZoneAlerts.Concat(oosNws.ZoneAlerts))
        {
            diagnostics.Add($"[ZONE ALERT] {alert.Event} | area={alert.Area} | precision={alert.Precision} | expires={alert.Expires}");
        }

        var hazards = new List<MapHazard>();
        AddSpcHazards(spcData, hazards);
        hazards.AddRange(arNws.WarningHazards);
        hazards.AddRange(arNws.WatchHazards);
        hazards.AddRange(oosNws.WarningHazards);
        hazards.AddRange(oosNws.WatchHazards);
        AddFireRiskHazards(arData, oosData, counties, hazards);

        if (wildfireData is not null)
        {
            AddWildfireHazards(wildfireData, hazards);
        }
        AddEarthquakeHazards(usgsArData, "AR", hazards);
        AddEarthquakeHazards(usgsOosData, "OOS", hazards);

        var affectedSites = FindAffectedSites(mapRows, hazards);
        var arWarn = arNws.WarningCollection;
        var arWatch = arNws.WatchCollection;
        var oosWarn = oosNws.WarningCollection;
        var oosWatch = oosNws.WatchCollection;
        if (scopedViewport is { } mapViewport)
        {
            arWarn = (JsonObject?)RegionalGeoJsonViewportFilter.FilterToViewport(arWarn, mapViewport) ?? arWarn;
            arWatch = (JsonObject?)RegionalGeoJsonViewportFilter.FilterToViewport(arWatch, mapViewport) ?? arWatch;
            oosWarn = (JsonObject?)RegionalGeoJsonViewportFilter.FilterToViewport(oosWarn, mapViewport) ?? oosWarn;
            oosWatch = (JsonObject?)RegionalGeoJsonViewportFilter.FilterToViewport(oosWatch, mapViewport) ?? oosWatch;
        }
        var processedGeo = new JsonObject
        {
            ["ar_warn"] = arWarn,
            ["ar_watch"] = arWatch,
            ["oos_warn"] = oosWarn,
            ["oos_watch"] = oosWatch,
        };
        var result = new JsonArray
        {
            processedGeo,
            new JsonObject(),
            diagnostics,
            BuildToggledSites(affectedSites, toggles),
            BuildAffectedSites(affectedSites),
            BuildAnalytics(mapRows, affectedSites),
        };
        if (cacheKey is not null)
        {
            StoreCachedMap(cacheKey, result);
        }
        return result;
    }

    private static string BuildCacheKey(
        JsonObject? toggles,
        IEnumerable<string> selectedEvents,
        bool includeAnalytics,
        string? viewport,
        IReadOnlyList<JsonObject> mapRows,
        JsonNode? feedMetadata,
        JsonNode? arData,
        JsonNode? oosData,
        JsonNode? wildfireData)
    {
        var fingerprint = new JsonObject
        {
            ["toggles"] = toggles?.DeepClone(),
            ["selected_events"] = new JsonArray(selectedEvents.OrderBy(value => value, StringComparer.Ordinal)
                .Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
            ["include_analytics"] = includeAnalytics,
            ["viewport"] = viewport,
            ["map_rows"] = new JsonArray(mapRows.Select(row => (JsonNode?)row.DeepClone()).ToArray()),
            ["feeds"] = FeedVersionFingerprint(feedMetadata),
            ["nws_signature"] = NwsSignature(arData, oosData),
            ["wildfires"] = CloneProperty(wildfireData as JsonObject, "meta"),
        };
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint.ToJsonString())));
    }

    private static JsonArray NwsSignature(params JsonNode?[] layers)
    {
        var signatures = new List<(string Id, string Sent, string Expires)>();
        foreach (var layer in layers)
        {
            if (layer is not JsonObject collection || collection["features"] is not JsonArray features)
            {
                continue;
            }
            foreach (var feature in features.OfType<JsonObject>())
            {
                var properties = feature["properties"] as JsonObject;
                var id = IsTruthy(properties?["id"]) ? properties!["id"] : feature["id"];
                signatures.Add((
                    IsTruthy(id) ? ToPythonString(id) : "",
                    IsTruthy(properties?["sent"]) ? ToPythonString(properties!["sent"]) : "",
                    IsTruthy(properties?["expires"]) ? ToPythonString(properties!["expires"]) : ""));
            }
        }
        var result = new JsonArray();
        foreach (var signature in signatures.OrderBy(value => value.Id, StringComparer.Ordinal)
                     .ThenBy(value => value.Sent, StringComparer.Ordinal)
                     .ThenBy(value => value.Expires, StringComparer.Ordinal))
        {
            result.Add(new JsonArray(
                JsonValue.Create(signature.Id), JsonValue.Create(signature.Sent), JsonValue.Create(signature.Expires)));
        }
        return result;
    }

    private static JsonNode? FeedVersionFingerprint(JsonNode? metadata)
    {
        if (metadata is not JsonObject feeds)
        {
            return null;
        }
        string[] fields = ["updated_at", "last_success_at", "feature_count", "last_error", "last_http_status", "coverage"];
        var result = new JsonObject();
        foreach (var (name, value) in feeds)
        {
            if (name == "server_time" || value is not JsonObject status)
            {
                continue;
            }
            var feed = new JsonObject();
            foreach (var field in fields)
            {
                if (status.TryGetPropertyValue(field, out var fieldValue))
                {
                    feed[field] = fieldValue?.DeepClone();
                }
            }
            result[name] = feed;
        }
        return result;
    }

    private static JsonArray? TryGetCachedMap(string key)
    {
        lock (MapCacheLock)
        {
            var now = DateTime.UtcNow;
            foreach (var expired in MapCache.Where(entry => entry.Value.ExpiresAt <= now).Select(entry => entry.Key).ToArray())
            {
                MapCache.Remove(expired);
            }
            return MapCache.TryGetValue(key, out var cached)
                ? (JsonArray)cached.Result.DeepClone()
                : null;
        }
    }

    private static void StoreCachedMap(string key, JsonArray result)
    {
        lock (MapCacheLock)
        {
            var now = DateTime.UtcNow;
            foreach (var expired in MapCache.Where(entry => entry.Value.ExpiresAt <= now).Select(entry => entry.Key).ToArray())
            {
                MapCache.Remove(expired);
            }
            if (!MapCache.ContainsKey(key) && MapCache.Count >= 16)
            {
                var oldest = MapCache.MinBy(entry => entry.Value.CreatedAt).Key;
                MapCache.Remove(oldest);
            }
            MapCache[key] = new MapCacheEntry(now.AddSeconds(120), now, (JsonArray)result.DeepClone());
        }
    }

    private static string[] RequestedFeeds(JsonObject? toggles, bool includeAnalytics)
    {
        var feeds = new HashSet<string>(StringComparer.Ordinal);
        if (includeAnalytics || ReadBoolean(GetToggle(toggles, "spc", false)))
        {
            feeds.Add("spc_day1");
        }
        if (includeAnalytics || ReadBoolean(GetToggle(toggles, "warn", false))
            || ReadBoolean(GetToggle(toggles, "watch", false))
            || ReadBoolean(GetToggle(toggles, "fire_risk", false)))
        {
            feeds.Add("nws_ar");
        }
        if (includeAnalytics || ReadBoolean(GetToggle(toggles, "oos", false)))
        {
            feeds.Add("nws_oos");
        }
        if (includeAnalytics || ReadBoolean(GetToggle(toggles, "earthquakes", false)))
        {
            feeds.Add("usgs_ar");
            feeds.Add("usgs_oos");
        }
        return feeds.OrderBy(name => name, StringComparer.Ordinal).ToArray();
    }

    private static ProcessedNws ProcessNwsAlerts(
        JsonNode? data,
        string region,
        bool isOutOfState,
        IReadOnlySet<string> selectedEvents,
        IReadOnlyDictionary<string, RegionalCountyGeometry> counties)
    {
        var warningFeatures = new JsonArray();
        var watchFeatures = new JsonArray();
        var warningHazards = new List<MapHazard>();
        var watchHazards = new List<MapHazard>();
        var zoneAlerts = new List<ZoneAlert>();
        var diagnostics = new List<string>();
        if (data is not JsonObject collection || collection["features"] is not JsonArray features)
        {
            diagnostics.Add($"[WARN] {region} data empty or missing 'features'.");
            return new ProcessedNws(
                FeatureCollection(warningFeatures), FeatureCollection(watchFeatures),
                warningHazards, watchHazards, zoneAlerts, diagnostics);
        }

        foreach (var feature in features.OfType<JsonObject>())
        {
            var properties = feature["properties"] as JsonObject;
            var eventType = PythonPropertyString(properties, "event", "Unknown");
            var headline = PythonPropertyString(properties, "headline", "");
            if (!selectedEvents.Contains(eventType))
            {
                continue;
            }

            var geometries = new List<JsonNode>();
            if (feature["geometry"] is JsonObject geometry)
            {
                geometries.Add(geometry.DeepClone());
            }
            else if (feature["geometry"] is null)
            {
                foreach (var fips in AlertCountyFips(properties))
                {
                    if (counties.TryGetValue(fips, out var county)
                        && (isOutOfState ? BorderStateFips.Contains(county.StateFips) : county.StateFips == "05"))
                    {
                        geometries.Add(county.Geometry.DeepClone());
                    }
                }
                if (geometries.Count == 0)
                {
                    var prefix = isOutOfState ? "[OOS]" : "[AR]";
                    zoneAlerts.Add(new ZoneAlert(
                        $"{prefix} {eventType}",
                        PropertyString(properties, "areaDesc", "Unknown"),
                        PropertyString(properties, "noc_coverage_precision", "zone_unresolved"),
                        PropertyString(properties, "expires", "unknown")));
                    continue;
                }
            }

            var isPds = eventType.Contains("PDS", StringComparison.Ordinal)
                || headline.Contains("Particularly Dangerous Situation", StringComparison.Ordinal)
                || headline.Contains("PDS", StringComparison.Ordinal);
            var isSevere = eventType.Contains("Warning", StringComparison.Ordinal)
                || eventType.Contains("Emergency", StringComparison.Ordinal) || isPds;
            var severity = isPds && !eventType.Contains("Warning", StringComparison.Ordinal)
                && !eventType.Contains("Emergency", StringComparison.Ordinal)
                    ? "PDS Watch"
                    : isSevere ? "Warning" : "Watch/Advisory";
            var prefixText = isOutOfState ? "[OOS]" : "[AR]";
            var fillColor = HazardColor(eventType, severity, isOutOfState);
            var lineColor = fillColor.Take(3).Select(color => Math.Min(255, color + 60)).Append(255).ToArray();

            foreach (var hazardGeometry in geometries)
            {
                var outputProperties = new JsonObject
                {
                    ["info"] = $"{prefixText} {eventType}",
                    ["severity"] = severity,
                    ["event"] = eventType,
                    ["headline"] = headline,
                    ["id"] = CloneProperty(properties, "id"),
                    ["effective"] = CloneProperty(properties, "effective"),
                    ["expires"] = CloneProperty(properties, "expires"),
                    ["ends"] = CloneTruthyFallback(properties, "ends", "eventEndingTime"),
                    ["messageType"] = ClonePropertyOrDefault(properties, "messageType", "Alert"),
                    ["coverage_precision"] = ClonePropertyOrDefault(properties, "noc_coverage_precision", "alert_geometry"),
                    ["fill_color"] = ColorArray(fillColor),
                    ["line_color"] = ColorArray(lineColor),
                };
                var outputFeature = new JsonObject
                {
                    ["type"] = "Feature",
                    ["geometry"] = hazardGeometry.DeepClone(),
                    ["properties"] = outputProperties,
                };
                var hazard = new MapHazard(
                    $"{prefixText} {eventType}", severity, hazardGeometry,
                    CloneProperty(properties, "expires"), CloneProperty(properties, "effective"));
                if (isSevere)
                {
                    warningFeatures.Add(outputFeature);
                    warningHazards.Add(hazard);
                }
                else
                {
                    watchFeatures.Add(outputFeature);
                    watchHazards.Add(hazard);
                }
            }
        }

        return new ProcessedNws(
            FeatureCollection(warningFeatures), FeatureCollection(watchFeatures),
            warningHazards, watchHazards, zoneAlerts, diagnostics);
    }

    private static void AddSpcHazards(JsonNode? data, ICollection<MapHazard> hazards)
    {
        if (data is not JsonObject collection || collection["features"] is not JsonArray features)
        {
            return;
        }
        foreach (var feature in features.OfType<JsonObject>())
        {
            if (feature["geometry"] is not JsonObject geometry)
            {
                continue;
            }
            var properties = feature["properties"] as JsonObject;
            var label = PythonPropertyString(properties, "LABEL", "");
            hazards.Add(new MapHazard($"SPC: {label}", "Watch", geometry.DeepClone()));
        }
    }

    private static void AddFireRiskHazards(
        JsonNode? arData,
        JsonNode? oosData,
        IReadOnlyDictionary<string, RegionalCountyGeometry> counties,
        ICollection<MapHazard> hazards)
    {
        var fireCounties = new Dictionary<string, MapHazard>(StringComparer.Ordinal);
        foreach (var data in new[] { arData, oosData })
        {
            if (data is not JsonObject collection || collection["features"] is not JsonArray features)
            {
                continue;
            }
            foreach (var feature in features.OfType<JsonObject>())
            {
                var properties = feature["properties"] as JsonObject;
                var eventType = PropertyString(properties, "event", "");
                if (!FireRiskEventTerms.Any(term => eventType.Contains(term, StringComparison.Ordinal)))
                {
                    continue;
                }
                foreach (var fips in SameCountyFips(properties))
                {
                    if (counties.TryGetValue(fips, out var county) && county.StateFips == "05")
                    {
                        fireCounties[fips] = new MapHazard(
                            $"Wildfire Risk: {eventType}", "High", county.Geometry,
                            CloneProperty(properties, "expires"));
                    }
                }
            }
        }
        foreach (var hazard in fireCounties.Values)
        {
            hazards.Add(hazard);
        }
    }

    private static void AddWildfireHazards(JsonNode? data, ICollection<MapHazard> hazards)
    {
        if (data is not JsonObject payload || payload["incidents"] is not JsonArray incidents)
        {
            return;
        }
        var perimeters = new Dictionary<string, JsonNode>(StringComparer.OrdinalIgnoreCase);
        if (payload["perimeters"] is JsonArray perimeterFeatures)
        {
            foreach (var perimeter in perimeterFeatures.OfType<JsonObject>())
            {
                var id = NormalizeFireId(PropertyString(perimeter, "irwin_id", ""));
                if (id.Length > 0 && perimeter["geometry"] is JsonObject geometry)
                {
                    perimeters[id] = geometry;
                }
            }
        }
        foreach (var incident in incidents.OfType<JsonObject>())
        {
            try
            {
                JsonNode geometry;
                var fireId = NormalizeFireId(PropertyString(incident, "irwin_id", ""));
                if (fireId.Length > 0 && perimeters.TryGetValue(fireId, out var perimeter))
                {
                    geometry = perimeter.DeepClone();
                }
                else
                {
                    if (!TryNumber(incident["lon"], out var longitude)
                        || !TryNumber(incident["lat"], out var latitude))
                    {
                        continue;
                    }
                    var acres = TryNumber(incident["acres"], out var parsedAcres) ? parsedAcres : 0;
                    if (acres <= 1.0)
                    {
                        var longitudeScale = 1.0 / (69.172 * Math.Cos(latitude * Math.PI / 180.0));
                        geometry = CreateEllipse(longitude, latitude, longitudeScale, 1.0 / 69.0);
                    }
                    else
                    {
                        geometry = CreateEllipse(longitude, latitude, 0.03, 0.03);
                    }
                }
                hazards.Add(new MapHazard(
                    $"Active Wildfire: {PropertyString(incident, "name", "Unknown Fire")}",
                    "High", geometry));
            }
            catch (ArgumentException)
            {
                // Ignore one malformed provider feature and keep the remaining map usable.
            }
        }
    }

    private static void AddEarthquakeHazards(JsonNode? data, string region, ICollection<MapHazard> hazards)
    {
        if (data is not JsonObject collection || collection["features"] is not JsonArray features)
        {
            return;
        }
        foreach (var feature in features.OfType<JsonObject>())
        {
            var properties = feature["properties"] as JsonObject;
            var magnitude = TryNumber(properties?["mag"], out var parsedMagnitude) ? parsedMagnitude : 0;
            if (magnitude < 2.0
                || feature["geometry"] is not JsonObject geometry
                || geometry["coordinates"] is not JsonArray coordinates
                || coordinates.Count < 2
                || !TryNumber(coordinates[0], out var longitude)
                || !TryNumber(coordinates[1], out var latitude))
            {
                continue;
            }
            var pointArea = CreateEllipse(longitude, latitude, 0.02, 0.02);
            hazards.Add(new MapHazard(
                $"EQ ({region}): M{magnitude.ToString("F1", CultureInfo.InvariantCulture)}",
                magnitude >= 4.0 ? "High" : "Medium", pointArea));
        }
    }

    private static List<AffectedSite> FindAffectedSites(
        IReadOnlyList<JsonObject> mapRows,
        IReadOnlyList<MapHazard> hazards)
    {
        // shortcut: Point-in-GeoJSON scans each hazard per site; add a spatial index if map profiling shows this is costly.
        var result = new List<AffectedSite>();
        foreach (var row in mapRows)
        {
            if (!TrySiteCoordinates(row, out var longitude, out var latitude))
            {
                continue;
            }
            var site = MappingValue(row, "Name", "Monitored Site", "name") ?? "Unknown";
            var type = MappingValue(row, "Type", "Facility Type", "loc_type", "type") ?? "General";
            var district = MappingValue(row, "District", "district") ?? "Central";
            var priority = MappingValue(row, "Priority", "priority") ?? "P3-Moderate";
            foreach (var hazard in hazards)
            {
                if (RegionalGeoJsonViewportFilter.CoversPoint(hazard.Geometry, longitude, latitude))
                {
                    result.Add(new AffectedSite(
                        site, type, district, priority, hazard.Event, hazard.Severity,
                        hazard.Expires?.DeepClone(), hazard.Effective?.DeepClone()));
                }
            }
        }
        return result;
    }

    private static JsonArray BuildAffectedSites(IEnumerable<AffectedSite> sites)
    {
        var result = new JsonArray();
        foreach (var site in sites)
        {
            result.Add(new JsonObject
            {
                ["Monitored Site"] = site.Site,
                ["Type"] = site.Type,
                ["District"] = site.District,
                ["Priority"] = site.Priority,
                ["Hazard"] = site.Hazard,
                ["Severity"] = site.Severity,
                ["HazardExpires"] = site.Expires?.DeepClone(),
                ["HazardEffective"] = site.Effective?.DeepClone(),
            });
        }
        return result;
    }

    private static JsonArray BuildToggledSites(IReadOnlyList<AffectedSite> sites, JsonObject? toggles)
    {
        var grouped = new Dictionary<string, ToggledSite>(StringComparer.Ordinal);
        foreach (var site in sites)
        {
            if (!IsVisible(site, toggles))
            {
                continue;
            }
            if (!grouped.TryGetValue(site.Site, out var row))
            {
                row = new ToggledSite(site);
                grouped.Add(site.Site, row);
            }
            row.AddHazard(site.Hazard);
        }
        var result = new JsonArray();
        foreach (var site in grouped.Values)
        {
            result.Add(new JsonObject
            {
                ["Monitored Site"] = site.Site,
                ["District"] = site.District,
                ["Facility Type"] = site.Type,
                ["Priority"] = site.Priority,
                ["Intersecting Hazards"] = string.Join(", ", site.Hazards),
            });
        }
        return result;
    }

    private static bool IsVisible(AffectedSite site, JsonObject? toggles)
    {
        var hazard = site.Hazard.ToUpperInvariant();
        if (hazard.Contains("SPC:", StringComparison.Ordinal) && ReadBoolean(GetToggle(toggles, "spc", true))) return true;
        if (hazard.Contains("WILDFIRE RISK:", StringComparison.Ordinal) && ReadBoolean(GetToggle(toggles, "fire_risk", false))) return true;
        if (hazard.Contains("ACTIVE WILDFIRE:", StringComparison.Ordinal) && ReadBoolean(GetToggle(toggles, "active_wildfires", false))) return true;
        if (hazard.Contains("EQ (", StringComparison.Ordinal) && ReadBoolean(GetToggle(toggles, "earthquakes", true))) return true;
        if (hazard.Contains("[OOS]", StringComparison.Ordinal) && ReadBoolean(GetToggle(toggles, "oos", true))) return true;
        if (hazard.Contains("[AR]", StringComparison.Ordinal) && site.Severity == "Warning")
            return ReadBoolean(GetToggle(toggles, "warn", true));
        if (hazard.Contains("[AR]", StringComparison.Ordinal) && site.Severity == "Watch/Advisory")
            return ReadBoolean(GetToggle(toggles, "watch", true));
        return false;
    }

    private static JsonObject BuildAnalytics(IReadOnlyList<JsonObject> mapRows, IReadOnlyList<AffectedSite> sites)
    {
        var severityRank = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["HIGH"] = 100, ["MDT"] = 90, ["ENH"] = 80, ["SLGT"] = 70, ["MRGL"] = 60, ["TSTM"] = 50,
            ["EXTREME"] = 95, ["SEVERE"] = 85, ["MODERATE"] = 75, ["MINOR"] = 65,
            ["WARNING"] = 85, ["WATCH"] = 75, ["ADVISORY"] = 65, ["STATEMENT"] = 55, ["NONE"] = 0,
        };
        var worstBySite = new Dictionary<string, (int Rank, AffectedSite Site)>(StringComparer.Ordinal);
        var spcRisks = new Dictionary<string, string>(StringComparer.Ordinal);
        var nwsAlerts = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var site in sites)
        {
            var rank = RankHazard(site.Hazard, severityRank);
            if (!worstBySite.TryGetValue(site.Site, out var prior) || rank > prior.Rank)
            {
                worstBySite[site.Site] = (rank, site);
            }
            var hazard = site.Hazard.ToUpperInvariant();
            if (hazard.Contains("SPC:", StringComparison.Ordinal))
            {
                var level = new[] { "HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM" }
                    .FirstOrDefault(candidate => hazard.Contains(candidate, StringComparison.Ordinal)) ?? "TSTM";
                if (severityRank.GetValueOrDefault(level) > severityRank.GetValueOrDefault(spcRisks.GetValueOrDefault(site.Site, "NONE")))
                {
                    spcRisks[site.Site] = level;
                }
            }
            else
            {
                var level = new[] { "WARNING", "WATCH", "ADVISORY" }
                    .FirstOrDefault(candidate => hazard.Contains(candidate, StringComparison.Ordinal)) ?? "STATEMENT";
                if (severityRank.GetValueOrDefault(level) > severityRank.GetValueOrDefault(nwsAlerts.GetValueOrDefault(site.Site, "NONE")))
                {
                    nwsAlerts[site.Site] = level;
                }
            }
        }

        var worstRows = worstBySite.Values.OrderByDescending(value => value.Rank).Select(value => value.Site).ToArray();
        var primaryLabels = worstRows.Select(site => PrimaryLabel(site.Hazard)).ToHashSet(StringComparer.Ordinal);
        var analytics = new JsonObject
        {
            ["total_sites"] = mapRows.Count,
            ["at_risk_sites"] = worstRows.Length,
            ["highest_risk"] = worstRows.Length > 0 ? PrimaryLabel(worstRows[0].Hazard) : "None",
            ["spc_distribution"] = OrderedDistribution(
                mapRows.Select(row => MappingValue(row, "Name", "name", "Monitored Site") ?? "None")
                    .Select(site => spcRisks.GetValueOrDefault(site, "None")),
                ["HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "None"], "SPC Risk"),
            ["nws_distribution"] = OrderedDistribution(
                mapRows.Select(row => MappingValue(row, "Name", "name", "Monitored Site") ?? "None")
                    .Select(site => nwsAlerts.GetValueOrDefault(site, "None")),
                ["WARNING", "WATCH", "ADVISORY", "STATEMENT", "None"], "NWS Alert"),
            ["type_distribution"] = MostCommon(worstRows.Select(site => site.Type), "Facility Type", "Count"),
            ["district_distribution"] = MostCommon(worstRows.Select(site => site.District), "District", "Count"),
            ["priority_risk_matrix"] = RiskMatrix(worstRows, site => site.Priority, "Priority", primaryLabels),
            ["type_risk_matrix"] = RiskMatrix(worstRows, site => site.Type, "Type", primaryLabels),
            ["district_risk_matrix"] = RiskMatrix(worstRows, site => site.District, "District", primaryLabels),
        };
        return analytics;
    }

    private static JsonArray OrderedDistribution(IEnumerable<string> values, string[] order, string key)
    {
        var counts = values.GroupBy(value => value, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        var result = new JsonArray();
        foreach (var value in order.Select((label, index) => (label, index))
                     .OrderByDescending(item => counts.GetValueOrDefault(item.label))
                     .ThenBy(item => item.index))
        {
            result.Add(new JsonObject
            {
                [key] = value.label,
                ["count"] = counts.GetValueOrDefault(value.label),
            });
        }
        return result;
    }

    private static JsonArray MostCommon(IEnumerable<string> values, string key, string countKey)
    {
        var entries = values.Select((value, index) => (value, index))
            .GroupBy(item => item.value, StringComparer.Ordinal)
            .Select(group => (Value: group.Key, Count: group.Count(), First: group.Min(item => item.index)))
            .OrderByDescending(item => item.Count)
            .ThenBy(item => item.First);
        var result = new JsonArray();
        foreach (var entry in entries)
        {
            result.Add(new JsonObject { [key] = entry.Value, [countKey] = entry.Count });
        }
        return result;
    }

    private static JsonArray RiskMatrix(
        IEnumerable<AffectedSite> sites,
        Func<AffectedSite, string> valueSelector,
        string field,
        IReadOnlySet<string> labels)
    {
        var groups = sites.GroupBy(valueSelector, StringComparer.Ordinal)
            .OrderBy(group => group.Key, StringComparer.Ordinal);
        var result = new JsonArray();
        foreach (var group in groups)
        {
            var counts = group.Select(site => PrimaryLabel(site.Hazard))
                .GroupBy(label => label, StringComparer.Ordinal)
                .ToDictionary(labelsGroup => labelsGroup.Key, labelsGroup => labelsGroup.Count(), StringComparer.Ordinal);
            var row = new JsonObject { [field] = group.Key };
            foreach (var label in labels.OrderBy(value => value, StringComparer.Ordinal))
            {
                row[label] = counts.GetValueOrDefault(label);
            }
            result.Add(row);
        }
        return result;
    }

    private static int RankHazard(string hazard, IReadOnlyDictionary<string, int> ranks) =>
        ranks.Where(pair => hazard.ToUpperInvariant().Contains(pair.Key, StringComparison.Ordinal))
            .Select(pair => pair.Value)
            .DefaultIfEmpty(10)
            .Max();

    private static string PrimaryLabel(string hazard)
    {
        var text = hazard.ToUpperInvariant();
        return new[] { "HIGH", "MDT", "ENH", "SLGT", "MRGL", "TSTM", "WARNING", "WATCH", "ADVISORY" }
            .FirstOrDefault(label => text.Contains(label, StringComparison.Ordinal)) ?? "OTHER";
    }

    private static Wgs84Box? ParseViewport(JsonNode? value)
    {
        if (value is null || value is JsonValue stringValue
            && stringValue.TryGetValue<string>(out var emptyText) && emptyText.Length == 0)
        {
            return null;
        }
        double[] values;
        if (value is JsonValue textValue && textValue.TryGetValue<string>(out var bboxText))
        {
            values = bboxText.Split(',').Select(part => TryParseNumber(part, out var number) ? number : double.NaN).ToArray();
        }
        else if (value is JsonArray array)
        {
            values = array.Select(part => TryNumber(part, out var number) ? number : double.NaN).ToArray();
        }
        else
        {
            throw new ArgumentException("bbox must contain west,south,east,north coordinates.");
        }
        if (values.Length != 4 || values.Any(number => !double.IsFinite(number)))
        {
            throw new ArgumentException("bbox must contain four finite coordinates.");
        }
        var bounds = new Wgs84Box(values[0], values[1], values[2], values[3]);
        if (!(bounds.West >= -180 && bounds.West < bounds.East && bounds.East <= 180
              && bounds.South >= -90 && bounds.South < bounds.North && bounds.North <= 90))
        {
            throw new ArgumentException("bbox coordinates are outside valid WGS84 bounds.");
        }
        return bounds;
    }

    private static JsonNode? FilterCurrentLegacyAlerts(JsonNode? data) =>
        data is JsonObject collection && collection["features"] is JsonArray
            ? RegionalGeoJsonViewportFilter.FilterCurrentAlerts(collection, DateTime.UtcNow)
            : data;

    private static string FormatViewport(Wgs84Box box) => string.Join(',',
        box.West.ToString("R", CultureInfo.InvariantCulture),
        box.South.ToString("R", CultureInfo.InvariantCulture),
        box.East.ToString("R", CultureInfo.InvariantCulture),
        box.North.ToString("R", CultureInfo.InvariantCulture));

    private static List<JsonObject> SelectAuthorizedMapRows(
        JsonNode? value,
        IReadOnlyList<MonitoredLocationEntry> authorizedLocations)
    {
        var rows = value is JsonArray array ? array.OfType<JsonObject>().ToList() : [];
        var siteColumn = new[] { "Monitored Site", "name", "Name" }
            .FirstOrDefault(name => rows.Any(row => row.ContainsKey(name)));
        if (siteColumn is null)
        {
            return [];
        }
        var locationsByName = authorizedLocations
            .Where(location => !string.IsNullOrEmpty(location.Name))
            .GroupBy(location => location.Name!, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var result = new List<JsonObject>();
        foreach (var row in rows)
        {
            if (locationsByName.TryGetValue(MappingValue(row, siteColumn) ?? "", out var location))
            {
                result.Add(new JsonObject
                {
                    ["Name"] = location.Name,
                    ["Type"] = location.LocationType,
                    ["District"] = location.District,
                    ["Priority"] = location.Priority,
                    ["Lat"] = location.Latitude,
                    ["Lon"] = location.Longitude,
                    ["current_spc_risk"] = location.CurrentSpcRisk,
                });
            }
        }
        return result;
    }

    private static bool SiteIsInViewport(JsonObject row, Wgs84Box viewport)
    {
        var longitudeNode = row.ContainsKey("Lon") ? row["Lon"] : row["lon"];
        var latitudeNode = row.ContainsKey("Lat") ? row["Lat"] : row["lat"];
        return TryNumber(longitudeNode, out var longitude) && TryNumber(latitudeNode, out var latitude)
            && longitude >= viewport.West && longitude <= viewport.East
            && latitude >= viewport.South && latitude <= viewport.North;
    }

    private static bool TrySiteCoordinates(JsonObject row, out double longitude, out double latitude)
    {
        var longitudeNode = FirstNonNull(row, "Lon", "lon");
        var latitudeNode = FirstNonNull(row, "Lat", "lat");
        var hasLongitude = TryNumber(longitudeNode, out longitude);
        var hasLatitude = TryNumber(latitudeNode, out latitude);
        return hasLongitude && hasLatitude;
    }

    private static string? MappingValue(JsonObject row, params string[] keys)
    {
        var value = FirstNonNull(row, keys);
        return value is null ? null : ToPythonString(value);
    }

    private static JsonNode? FirstNonNull(JsonObject row, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (row.TryGetPropertyValue(key, out var value) && value is not null)
            {
                return value;
            }
        }
        return null;
    }

    private static List<string> AlertCountyFips(JsonObject? properties)
    {
        var geocode = properties?["geocode"] as JsonObject;
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var code in CodeValues(geocode?["SAME"]))
        {
            var digits = Digits(code);
            if (digits.Length >= 5)
            {
                result.Add(digits[^5..]);
            }
        }
        foreach (var code in CodeValues(geocode?["UGC"]))
        {
            if (code.Length >= 6 && code[2] == 'C')
            {
                var state = StateFipsCodes.FirstOrDefault(entry => entry.StartsWith(code[..2] + ":", StringComparison.Ordinal));
                if (state is not null)
                {
                    result.Add(state[3..] + code[^3..]);
                }
            }
        }
        return result.ToList();
    }

    private static IEnumerable<string> SameCountyFips(JsonObject? properties)
    {
        foreach (var code in CodeValues((properties?["geocode"] as JsonObject)?["SAME"]))
        {
            var digits = Digits(code);
            if (digits.Length >= 5)
            {
                yield return digits[^5..];
            }
        }
    }

    private static IEnumerable<string> CodeValues(JsonNode? value)
    {
        IEnumerable<string> codes = value is JsonArray array
            ? array.Where(item => item is not null).Select(ToPythonString)
            : (value is null ? "" : ToPythonString(value))
                .Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return codes.Select(code => code.Trim().ToUpperInvariant()).ToArray();
    }

    private static string Digits(string value) => new(value.Where(char.IsDigit).ToArray());

    private static JsonObject FeatureCollection(JsonArray features) => new()
    {
        ["type"] = "FeatureCollection",
        ["features"] = features,
    };

    private static JsonArray ColorArray(IReadOnlyList<int> colors) =>
        new(colors.Select(color => (JsonNode?)JsonValue.Create(color)).ToArray());

    private static int[] HazardColor(string eventType, string severity, bool isOutOfState)
    {
        var eventLower = eventType.ToLowerInvariant();
        int[] color;
        if (eventLower.Contains("tornado", StringComparison.Ordinal)) color = severity == "Warning" ? [180, 0, 0, 100] : [180, 0, 0, 60];
        else if (eventLower.Contains("severe thunderstorm", StringComparison.Ordinal)) color = severity == "Warning" ? [255, 120, 0, 100] : [255, 140, 0, 60];
        else if (eventLower.Contains("flash flood", StringComparison.Ordinal)) color = severity == "Warning" ? [0, 180, 0, 100] : [0, 140, 0, 60];
        else if (eventLower.Contains("flood", StringComparison.Ordinal) && eventLower.Contains("watch", StringComparison.Ordinal)) color = [80, 140, 0, 60];
        else if (eventLower.Contains("flood", StringComparison.Ordinal)) color = severity == "Warning" ? [0, 150, 0, 100] : [80, 140, 0, 60];
        else if (eventLower.Contains("winter storm", StringComparison.Ordinal) || eventLower.Contains("winter weather", StringComparison.Ordinal)) color = severity == "Warning" ? [200, 90, 160, 100] : [180, 100, 140, 60];
        else if (eventLower.Contains("blizzard", StringComparison.Ordinal)) color = [180, 60, 180, 100];
        else if (eventLower.Contains("ice storm", StringComparison.Ordinal) || eventLower.Contains("freezing", StringComparison.Ordinal)) color = severity == "Warning" ? [160, 100, 140, 100] : [140, 100, 120, 60];
        else if (eventLower.Contains("heat", StringComparison.Ordinal)) color = severity == "Warning" ? [255, 140, 0, 100] : [255, 160, 0, 60];
        else if (eventLower.Contains("wind", StringComparison.Ordinal)) color = severity == "Warning" ? [255, 255, 0, 100] : [220, 220, 0, 60];
        else if (eventLower.Contains("red flag", StringComparison.Ordinal) || eventLower.Contains("fire weather", StringComparison.Ordinal) || eventLower.Contains("fire warning", StringComparison.Ordinal)) color = [255, 69, 0, 120];
        else if (eventLower.Contains("hurricane", StringComparison.Ordinal)) color = [200, 0, 200, 100];
        else if (eventLower.Contains("tropical storm", StringComparison.Ordinal)) color = [200, 80, 170, 100];
        else if (eventLower.Contains("snow squall", StringComparison.Ordinal)) color = [160, 190, 220, 100];
        else if (eventLower.Contains("special weather", StringComparison.Ordinal)) color = [100, 160, 220, 70];
        else if (eventLower.Contains("dense fog", StringComparison.Ordinal) || eventLower.Contains("dense smoke", StringComparison.Ordinal)) color = [140, 140, 160, 70];
        else if (eventLower.Contains("dust", StringComparison.Ordinal)) color = [180, 140, 80, 70];
        else if (eventLower.Contains("coastal", StringComparison.Ordinal) || eventLower.Contains("marine", StringComparison.Ordinal) || eventLower.Contains("high surf", StringComparison.Ordinal)) color = [0, 100, 180, 80];
        else if (eventLower.Contains("severe weather", StringComparison.Ordinal)) color = [255, 100, 0, 80];
        else if (severity == "Warning") color = [255, 60, 60, 100];
        else if (eventLower.Contains("watch", StringComparison.Ordinal)) color = [255, 165, 0, 60];
        else color = [255, 200, 0, 60];
        return isOutOfState ? [Math.Max(0, color[0] - 60), Math.Max(0, color[1] - 60), Math.Max(0, color[2] - 60), color[3]] : color;
    }

    private static JsonObject CreateEllipse(double longitude, double latitude, double longitudeRadius, double latitudeRadius)
    {
        if (!double.IsFinite(longitude) || !double.IsFinite(latitude)
            || !double.IsFinite(longitudeRadius) || !double.IsFinite(latitudeRadius))
        {
            throw new ArgumentException("Map geometry coordinates must be finite.");
        }
        const int segments = 64;
        var ring = new JsonArray();
        for (var index = 0; index <= segments; index++)
        {
            var angle = 2 * Math.PI * index / segments;
            ring.Add(new JsonArray(
                JsonValue.Create(longitude + Math.Cos(angle) * longitudeRadius),
                JsonValue.Create(latitude + Math.Sin(angle) * latitudeRadius)));
        }
        return new JsonObject
        {
            ["type"] = "Polygon",
            ["coordinates"] = new JsonArray { ring },
        };
    }

    private static string NormalizeFireId(string value) =>
        value.Replace("{", "", StringComparison.Ordinal)
            .Replace("}", "", StringComparison.Ordinal)
            .Trim()
            .ToLowerInvariant();

    private static JsonNode? GetToggle(JsonObject? toggles, string name, bool defaultValue) =>
        toggles is not null && toggles.TryGetPropertyValue(name, out var value)
            ? value?.DeepClone()
            : JsonValue.Create(defaultValue);

    private static bool ReadBoolean(JsonNode? value)
    {
        if (value is null)
        {
            return false;
        }
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<bool>(out var boolean))
        {
            return boolean;
        }
        if (value is JsonValue stringValue && stringValue.TryGetValue<string>(out var text))
        {
            return text.Length > 0;
        }
        if (value is JsonArray array)
        {
            return array.Count > 0;
        }
        if (value is JsonObject obj)
        {
            return obj.Count > 0;
        }
        return value is not JsonValue || TryNumber(value, out var number) && number != 0;
    }

    private static bool TryNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue)
        {
            if (jsonValue.TryGetValue<double>(out number) && double.IsFinite(number))
            {
                return true;
            }
            if (jsonValue.TryGetValue<string>(out var text) && TryParseNumber(text, out number))
            {
                return true;
            }
            if (TryParseNumber(jsonValue.ToJsonString(), out number))
            {
                return true;
            }
        }
        number = 0;
        return false;
    }

    private static bool TryParseNumber(string value, out double number) =>
        double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
        && double.IsFinite(number);

    private static string ToPythonString(JsonNode? value) => value switch
    {
        null => "None",
        JsonValue jsonValue when jsonValue.TryGetValue<string>(out var text) => text,
        JsonValue jsonValue when jsonValue.TryGetValue<bool>(out var boolean) => boolean ? "True" : "False",
        _ => value.ToJsonString(),
    };

    private static string PythonPropertyString(JsonObject? source, string key, string missingDefault) =>
        source is not null && source.TryGetPropertyValue(key, out var value)
            ? ToPythonString(value)
            : missingDefault;

    private static string PropertyString(JsonObject? source, string key, string missingDefault) =>
        source is not null && source.TryGetPropertyValue(key, out var value) && value is not null
            ? ToPythonString(value)
            : missingDefault;

    private static JsonNode? CloneProperty(JsonObject? source, string key) =>
        source is not null && source.TryGetPropertyValue(key, out var value) ? value?.DeepClone() : null;

    private static JsonNode? ClonePropertyOrDefault(JsonObject? source, string key, string defaultValue) =>
        source is not null && source.TryGetPropertyValue(key, out var value)
            ? value?.DeepClone()
            : JsonValue.Create(defaultValue);

    private static JsonNode? CloneTruthyFallback(JsonObject? source, string primaryKey, string fallbackKey)
    {
        var primary = source is not null && source.TryGetPropertyValue(primaryKey, out var value)
            ? value
            : null;
        return (IsTruthy(primary) ? primary : CloneProperty(source, fallbackKey))?.DeepClone();
    }

    private static bool IsTruthy(JsonNode? value)
    {
        if (value is null)
        {
            return false;
        }
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text))
        {
            return text.Length > 0;
        }
        if (value is JsonValue booleanValue && booleanValue.TryGetValue<bool>(out var boolean))
        {
            return boolean;
        }
        if (value is JsonArray array)
        {
            return array.Count > 0;
        }
        if (value is JsonObject obj)
        {
            return obj.Count > 0;
        }
        return value is not JsonValue || !TryNumber(value, out var number) || number != 0;
    }

    private sealed record MapHazard(string Event, string Severity, JsonNode Geometry, JsonNode? Expires = null, JsonNode? Effective = null);
    private sealed record ZoneAlert(string Event, string Area, string Precision, string Expires);
    private sealed record AffectedSite(
        string Site,
        string Type,
        string District,
        string Priority,
        string Hazard,
        string Severity,
        JsonNode? Expires,
        JsonNode? Effective);
    private sealed record ProcessedNws(
        JsonObject WarningCollection,
        JsonObject WatchCollection,
        List<MapHazard> WarningHazards,
        List<MapHazard> WatchHazards,
        List<ZoneAlert> ZoneAlerts,
        List<string> Diagnostics);
    private sealed record MapCacheEntry(DateTime ExpiresAt, DateTime CreatedAt, JsonArray Result);

    private sealed class ToggledSite(AffectedSite site)
    {
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
        public string Site { get; } = site.Site;
        public string Type { get; } = site.Type;
        public string District { get; } = site.District;
        public string Priority { get; } = site.Priority;
        public List<string> Hazards { get; } = [];

        public void AddHazard(string hazard)
        {
            if (_seen.Add(hazard))
            {
                Hazards.Add(hazard);
            }
        }
    }
}
