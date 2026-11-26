using System.Globalization;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Domain.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed class RegionalDataQueries(IRegionalDataStore regionalData)
{
    private static readonly string[] GeoJsonFeeds =
    ["spc_day1", "spc_day2", "spc_day3", "nws_ar", "nws_oos", "usgs_ar", "usgs_oos"];
    private static readonly string[] NwsGeoJsonFeeds = ["nws_ar", "nws_oos"];
    private static readonly string[] WeatherLogFeeds = ["nws_ar", "nws_oos", "usgs_ar", "usgs_oos"];
    private static readonly string[] StatusFeeds = [.. GeoJsonFeeds, "nws_region"];

    public async Task<JsonObject> GetGeoJsonAsync(
        string? layers,
        string? bbox,
        CancellationToken cancellationToken)
    {
        var requested = ParseLayers(layers);
        var viewport = ParseBoundingBox(bbox);
        var now = DateTime.UtcNow;
        var feeds = await regionalData.GetGeoJsonLayersAsync(requested, cancellationToken);
        var result = new JsonObject();
        foreach (var name in requested)
        {
            var json = feeds.GetValueOrDefault(name);
            JsonNode? collection = json is null ? null : JsonNode.Parse(json);
            if (NwsGeoJsonFeeds.Contains(name, StringComparer.Ordinal))
            {
                collection = RegionalGeoJsonViewportFilter.FilterCurrentAlerts(collection, now);
            }
            if (viewport is { } bounds)
            {
                collection = RegionalGeoJsonViewportFilter.FilterToViewport(collection, bounds);
            }
            result[name] = collection;
        }

        var activeEvents = await regionalData.GetActiveNwsEventTypesAsync(now, cancellationToken);
        var eventTypes = new JsonArray();
        foreach (var eventType in activeEvents)
        {
            eventTypes.Add(eventType);
        }
        result["nws_events"] = eventTypes;
        var statuses = await regionalData.GetGeoJsonFeedStatusesAsync(StatusFeeds, cancellationToken);
        result["meta"] = BuildStatusMetadata(statuses, now);
        return result;
    }

    public async Task<JsonArray> GetWeatherAlertsLogAsync(CancellationToken cancellationToken)
    {
        var layers = await regionalData.GetGeoJsonLayersAsync(WeatherLogFeeds, cancellationToken);
        var now = DateTime.UtcNow;
        var result = new JsonArray();
        AddNwsAlerts(result, CurrentLayer(layers, "nws_ar", now), "AR");
        AddNwsAlerts(result, CurrentLayer(layers, "nws_oos", now), "OOS");
        AddEarthquakes(result, ParseLayer(layers, "usgs_ar"), "AR");
        AddEarthquakes(result, ParseLayer(layers, "usgs_oos"), "OOS");
        return result;
    }

    private static string[] ParseLayers(string? layers)
    {
        HashSet<string> requested;
        if (layers is null)
        {
            requested = GeoJsonFeeds.ToHashSet(StringComparer.Ordinal);
        }
        else if (string.Equals(layers.Trim(), "summary", StringComparison.OrdinalIgnoreCase))
        {
            requested = new HashSet<string>(StringComparer.Ordinal);
        }
        else
        {
            requested = layers.Split(',', StringSplitOptions.RemoveEmptyEntries)
                .Select(name => name.Trim())
                .Where(name => name.Length > 0)
                .ToHashSet(StringComparer.Ordinal);
        }

        var unknown = requested.Except(GeoJsonFeeds, StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unknown regional GeoJSON layer(s): {string.Join(", ", unknown)}");
        }
        return requested.OrderBy(name => name, StringComparer.Ordinal).ToArray();
    }

    private static Wgs84Box? ParseBoundingBox(string? value)
    {
        if (value is null or "")
        {
            return null;
        }
        var parts = value.Split(',');
        if (parts.Length != 4 || parts.Any(part =>
                !double.TryParse(part, NumberStyles.Float, CultureInfo.InvariantCulture, out var number)
                || !double.IsFinite(number)))
        {
            throw new ArgumentException("bbox must contain west,south,east,north coordinates.");
        }
        var west = double.Parse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture);
        var south = double.Parse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture);
        var east = double.Parse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture);
        var north = double.Parse(parts[3], NumberStyles.Float, CultureInfo.InvariantCulture);
        if (!(west >= -180 && west < east && east <= 180
            && south >= -90 && south < north && north <= 90))
        {
            throw new ArgumentException("bbox coordinates are outside valid WGS84 bounds.");
        }
        return new Wgs84Box(west, south, east, north);
    }

    private static JsonObject BuildStatusMetadata(
        IReadOnlyDictionary<string, GeoJsonFeedStatus> statuses,
        DateTime now)
    {
        var result = new JsonObject();
        foreach (var name in StatusFeeds)
        {
            statuses.TryGetValue(name, out var feed);
            var lastSuccess = feed?.LastSuccessAt ?? feed?.UpdatedAt;
            int? ageSeconds = lastSuccess is null
                ? null
                : Math.Max(0, (int)(now - lastSuccess.Value).TotalSeconds);
            var hasSuccess = lastSuccess is not null;
            var staleAfter = name.StartsWith("nws_", StringComparison.Ordinal)
                ? TimeSpan.FromSeconds(180)
                : TimeSpan.FromMinutes(15);
            var status = !string.IsNullOrEmpty(feed?.LastError)
                ? hasSuccess ? "stale" : "error"
                : !hasSuccess
                    ? feed?.LastAttemptAt is not null ? "error" : "missing"
                    : now - lastSuccess!.Value > staleAfter
                        ? "stale"
                        : feed?.FeatureCount == 0 ? "empty" : "ok";
            result[name] = new JsonObject
            {
                ["updated_at"] = IsoDate(feed?.UpdatedAt),
                ["last_attempt_at"] = IsoDate(feed?.LastAttemptAt),
                ["last_success_at"] = IsoDate(lastSuccess),
                ["age_seconds"] = ageSeconds,
                ["feature_count"] = feed is null ? 0 : feed.FeatureCount,
                ["status"] = status,
                ["last_error"] = feed?.LastError,
                ["last_http_status"] = feed?.LastHttpStatus,
                ["last_duration_ms"] = feed?.LastDurationMs,
                ["retry_after_at"] = IsoDate(feed?.RetryAfterAt),
                ["coverage"] = feed?.CoverageSummaryJson is { } coverage ? JsonNode.Parse(coverage) : null,
            };
        }

        result["server_time"] = IsoDate(now) + "Z";
        if (result["nws_region"] is JsonObject nwsStatus)
        {
            foreach (var layer in NwsGeoJsonFeeds)
            {
                var alias = (JsonObject)nwsStatus.DeepClone();
                alias["layer"] = layer;
                result[layer] = alias;
            }
        }
        return result;
    }

    private static JsonNode? CurrentLayer(
        IReadOnlyDictionary<string, string?> layers,
        string name,
        DateTime nowUtc) =>
        RegionalGeoJsonViewportFilter.FilterCurrentAlerts(ParseLayer(layers, name), nowUtc);

    private static JsonNode? ParseLayer(IReadOnlyDictionary<string, string?> layers, string name) =>
        layers.TryGetValue(name, out var json) && json is not null ? JsonNode.Parse(json) : null;

    private static void AddNwsAlerts(JsonArray results, JsonNode? layer, string region)
    {
        if (layer is not JsonObject collection || collection["features"] is not JsonArray features)
        {
            return;
        }
        foreach (var feature in features)
        {
            var properties = feature is JsonObject featureObject
                ? featureObject["properties"] as JsonObject
                : null;
            var eventName = ToPythonString(GetValue(properties, "event", "Unknown"));
            var expectedEnd = GetValue(properties, "ends", null);
            if (!IsTruthy(expectedEnd))
            {
                expectedEnd = GetValue(properties, "eventEndingTime", null);
            }
            results.Add(new JsonObject
            {
                ["Event"] = $"[{region}] {eventName}",
                ["Severity"] = CloneValue(properties, "severity", "Unknown"),
                ["Certainty"] = CloneValue(properties, "certainty", "Unknown"),
                ["Headline"] = CloneValue(properties, "headline", "No headline available."),
                ["Affected Area"] = CloneValue(properties, "areaDesc", "Unknown Area"),
                ["Sent"] = CloneValue(properties, "sent", "N/A"),
                ["Effective"] = CloneValue(properties, "effective", "N/A"),
                ["Expires"] = CloneValue(properties, "expires", "N/A"),
                ["Expected End"] = expectedEnd?.DeepClone(),
                ["Message Type"] = CloneValue(properties, "messageType", "Alert"),
                ["Alert ID"] = CloneValue(properties, "id", null),
                ["Coverage Precision"] = CloneValue(properties, "noc_coverage_precision", "alert_geometry"),
                ["Description"] = CloneValue(properties, "description", "No detailed description provided by NWS."),
                ["Instructions"] = CloneValue(properties, "instruction", "No explicit instructions provided."),
            });
        }
    }

    private static void AddEarthquakes(JsonArray results, JsonNode? layer, string region)
    {
        if (layer is not JsonObject collection || collection["features"] is not JsonArray features)
        {
            return;
        }
        foreach (var feature in features)
        {
            if (feature is not JsonObject featureObject)
            {
                continue;
            }
            var properties = featureObject["properties"] as JsonObject;
            var magnitude = ReadNumber(GetValue(properties, "mag", JsonValue.Create(0)));
            if (magnitude < 2.0)
            {
                continue;
            }
            var coordinates = (featureObject["geometry"] as JsonObject)?["coordinates"] as JsonArray;
            var depth = coordinates is { Count: > 2 } ? ReadNumber(coordinates[2]) : 0;
            var time = ReadNumber(GetValue(properties, "time", JsonValue.Create(0)));
            var timeText = time == 0 ? "Unknown" : FormatEarthquakeTime(time);
            var place = ToPythonString(GetValue(properties, "place", "Unknown"));
            var id = featureObject["id"]?.DeepClone();
            results.Add(new JsonObject
            {
                ["Event"] = $"[USGS {region}] Earthquake",
                ["Severity"] = EarthquakeSeverity(magnitude),
                ["Certainty"] = "Confirmed",
                ["Headline"] = $"M{magnitude.ToString("F1", CultureInfo.InvariantCulture)} Earthquake - {place}",
                ["Affected Area"] = $"{region} Region",
                ["Alert ID"] = id,
                ["Effective"] = timeText,
                ["Expires"] = "N/A",
                ["Description"] = $"Magnitude {magnitude.ToString("F1", CultureInfo.InvariantCulture)} earthquake at depth {depth.ToString("F1", CultureInfo.InvariantCulture)}km. Location: {place}",
                ["Instructions"] = "Monitor for aftershocks. Check structural integrity at nearby facilities.",
            });
        }
    }

    private static JsonNode? CloneValue(JsonObject? source, string key, object? defaultValue)
    {
        if (source?.ContainsKey(key) == true)
        {
            return source[key]?.DeepClone();
        }
        return JsonSerializerNode(defaultValue);
    }

    private static JsonNode? GetValue(JsonObject? source, string key, object? defaultValue) =>
        source?.ContainsKey(key) == true ? source[key] : JsonSerializerNode(defaultValue);

    private static JsonNode? JsonSerializerNode(object? value) =>
        value is null ? null : System.Text.Json.JsonSerializer.SerializeToNode(value);

    private static string ToPythonString(JsonNode? value)
    {
        if (value is null)
        {
            return "None";
        }
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text))
        {
            return text;
        }
        if (value is JsonValue booleanValue && booleanValue.TryGetValue<bool>(out var boolean))
        {
            return boolean ? "True" : "False";
        }
        return value.ToJsonString();
    }

    private static double ReadNumber(JsonNode? value)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out var number) && double.IsFinite(number))
        {
            return number;
        }
        return 0;
    }

    private static bool IsTruthy(JsonNode? value) => value switch
    {
        null => false,
        JsonValue jsonValue when jsonValue.TryGetValue<string>(out var text) => text.Length > 0,
        JsonValue jsonValue when jsonValue.TryGetValue<bool>(out var boolean) => boolean,
        JsonValue jsonValue when jsonValue.TryGetValue<double>(out var number) => number != 0,
        _ => true,
    };

    private static string FormatEarthquakeTime(double milliseconds)
    {
        try
        {
            var local = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeMilliseconds((long)milliseconds),
                TimeZoneInfo.FindSystemTimeZoneById("America/Chicago"));
            return local.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        }
        catch (ArgumentOutOfRangeException)
        {
            return "Unknown";
        }
    }

    private static string EarthquakeSeverity(double magnitude) => magnitude switch
    {
        >= 5.0 => "Severe",
        >= 4.0 => "High",
        >= 3.0 => "Moderate",
        _ => "Minor",
    };

    private static string? IsoDate(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
