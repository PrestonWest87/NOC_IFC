using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Regional;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.Integrations.Weather;

public sealed class RegionalHazardSyncClient(
    HttpClient httpClient,
    NwsForecastConfiguration nwsConfiguration,
    SqliteRegionalHazardSyncStore store,
    ArkansasFireCoverage coverage,
    IRegionalCountyGeometryProvider countyGeometry,
    IFacilityDirectoryStore facilities,
    IOperationalIntegrationSettingsStore integrationSettings,
    IRegionalWildfireProvider wildfires,
    WfcaWildfireSnapshotCache wildfireCache,
    IEmailSender emailSender) : IRegionalHazardSyncProvider
{
    private const string NwsFeedName = "nws_region";
    private const int MaxResponseBytes = 32 * 1024 * 1024;
    private static readonly string[] BorderStateCodes = ["LA", "TX", "MS", "MO", "OK", "TN"];
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
    private static readonly HashSet<string> BorderStateFips = ["22", "48", "28", "29", "40", "47"];
    private static readonly Dictionary<string, string> StateFipsByCode = new(StringComparer.Ordinal)
    {
        ["AR"] = "05", ["LA"] = "22", ["TX"] = "48", ["MS"] = "28",
        ["MO"] = "29", ["OK"] = "40", ["TN"] = "47",
    };
    private static readonly Dictionary<string, string> StateCodeByFips =
        StateFipsByCode.ToDictionary(pair => pair.Value, pair => pair.Key, StringComparer.Ordinal);
    private static readonly (string Name, string Url)[] SpcFeeds =
    [
        ("spc_day1", "https://www.spc.noaa.gov/products/outlook/day1otlk_cat.nolyr.geojson"),
        ("spc_day2", "https://www.spc.noaa.gov/products/outlook/day2otlk_cat.nolyr.geojson"),
        ("spc_day3", "https://www.spc.noaa.gov/products/outlook/day3otlk_cat.nolyr.geojson"),
    ];
    private const string NwsActiveUrl = "https://api.weather.gov/alerts/active?area=AR,LA,TX,MS,MO,OK,TN";

    public async Task<JsonObject> SyncNwsAlertsAsync(CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        var timer = Stopwatch.StartNew();
        var reservation = await store.ReserveNwsPollAsync(startedAt, cancellationToken);
        if (reservation.Status is "backoff" or "throttled")
        {
            var skipped = new JsonObject
            {
                ["status"] = reservation.Status,
                ["feed"] = NwsFeedName,
                ["message"] = reservation.Status == "backoff"
                    ? "NWS Retry-After window has not elapsed; polling is deferred."
                    : "A centralized NWS request was made within the last 60 seconds.",
            };
            AddDate(skipped, "last_attempt_at", reservation.LastAttemptAt);
            AddDate(skipped, "last_success_at", reservation.LastSuccessAt);
            AddDate(skipped, "retry_after_at", reservation.RetryAfterAt);
            return skipped;
        }
        if (reservation.Status != "reserved")
        {
            return new JsonObject { ["status"] = "error", ["feed"] = NwsFeedName, ["message"] = "NWS poll lease could not be acquired." };
        }

        int? httpStatus = null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, NwsActiveUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/geo+json"));
            request.Headers.TryAddWithoutValidation("User-Agent", BuildNwsUserAgent());
            if (EntityTagHeaderValue.TryParse(reservation.ETag, out var etag))
            {
                request.Headers.IfNoneMatch.Add(etag);
            }
            if (DateTimeOffset.TryParse(reservation.LastModified, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var modified))
            {
                request.Headers.IfModifiedSince = modified;
            }

            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            httpStatus = (int)response.StatusCode;
            var finishedAt = DateTime.UtcNow;
            var durationMs = ElapsedMilliseconds(timer);
            if (response.StatusCode == System.Net.HttpStatusCode.NotModified)
            {
                if (string.IsNullOrWhiteSpace(reservation.Data))
                {
                    const string error = "NWS returned 304 but no cached response body is available.";
                    await store.RecordNwsFailureAsync(startedAt, httpStatus, durationMs, error, null, cancellationToken);
                    await store.ClearNwsValidatorsAsync(cancellationToken);
                    return new JsonObject { ["status"] = "error", ["feed"] = NwsFeedName, ["url"] = NwsActiveUrl, ["message"] = error, ["http_status"] = httpStatus };
                }
                await store.RecordNwsNotModifiedAsync(finishedAt, durationMs, cancellationToken);
                return new JsonObject
                {
                    ["status"] = "not_modified",
                    ["feed"] = NwsFeedName,
                    ["url"] = NwsActiveUrl,
                    ["http_status"] = httpStatus,
                    ["feature_count"] = ReadFeatureCount(reservation.Data),
                };
            }
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                var retryAfter = ParseRetryAfter(response.Headers.RetryAfter, finishedAt);
                var message = $"HTTP {httpStatus}" + (response.Headers.RetryAfter is { } retry ? $"; Retry-After={retry}" : "");
                await store.RecordNwsFailureAsync(startedAt, httpStatus, durationMs, message, retryAfter, cancellationToken);
                return new JsonObject
                {
                    ["status"] = "error", ["feed"] = NwsFeedName, ["message"] = message, ["http_status"] = httpStatus,
                    ["url"] = NwsActiveUrl,
                };
            }

            var body = await ReadBodyAsync(response, cancellationToken);
            var source = JsonNode.Parse(body) as JsonObject
                ?? throw new InvalidDataException("NWS active alerts response was not a GeoJSON object.");
            var features = source["features"] as JsonArray
                ?? throw new InvalidDataException("NWS active alerts response did not contain a FeatureCollection.");
            var split = SplitAlerts(source, features, finishedAt);
            await store.SaveNwsSnapshotAsync(
                source.ToJsonString(),
                split.Arkansas.ToJsonString(),
                split.Border.ToJsonString(),
                split.Coverage.ToJsonString(),
                features.Count,
                split.ArkansasFeatures.Count,
                split.BorderFeatures.Count,
                response.Headers.ETag?.ToString() ?? reservation.ETag,
                response.Content.Headers.LastModified?.ToString("R", CultureInfo.InvariantCulture) ?? reservation.LastModified,
                finishedAt,
                durationMs,
                split.Hazards,
                split.References,
                cancellationToken);
            return new JsonObject
            {
                ["status"] = "ok",
                ["feed"] = NwsFeedName,
                ["url"] = NwsActiveUrl,
                ["http_status"] = httpStatus,
                ["feature_count"] = features.Count,
                ["arkansas_alerts"] = split.ArkansasFeatures.Count,
                ["border_alerts"] = split.BorderFeatures.Count,
                ["records_reconciled"] = split.Hazards.Count,
                ["coverage"] = split.Coverage.DeepClone(),
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var durationMs = ElapsedMilliseconds(timer);
            await store.RecordNwsFailureAsync(
                startedAt, httpStatus, durationMs, exception.Message, null, cancellationToken);
            return new JsonObject
            {
                ["status"] = "error", ["feed"] = NwsFeedName,
                ["url"] = NwsActiveUrl, ["message"] = exception.Message, ["http_status"] = httpStatus,
            };
        }
    }

    public async Task<JsonObject> SyncRegionalFeedsAsync(CancellationToken cancellationToken)
    {
        var spcTask = SyncSpcOutlooksAsync(cancellationToken);
        var arTask = SyncUsGsAsync("ar", "usgs_ar", cancellationToken);
        var borderTask = SyncUsGsAsync("oos", "usgs_oos", cancellationToken);
        var spc = await spcTask;
        var arkansas = await arTask;
        var border = await borderTask;

        if (arkansas.Data is not null && arkansas.Result["status"]?.GetValue<string>() == "ok")
        {
            await CheckEarthquakeProximityAsync(arkansas.Data, cancellationToken);
        }
        if (border.Data is not null && border.Result["status"]?.GetValue<string>() == "ok")
        {
            await CheckEarthquakeProximityAsync(border.Data, cancellationToken);
        }
        await CheckWildfireProximityAsync(cancellationToken);
        await wildfireCache.InvalidateAsync(cancellationToken);

        var feeds = new JsonObject
        {
            ["spc"] = spc,
            ["usgs_ar"] = arkansas.Result,
            ["usgs_oos"] = border.Result,
        };
        var failed = new JsonArray();
        if (spc["status"]?.GetValue<string>() != "ok") failed.Add("spc");
        if (arkansas.Result["status"]?.GetValue<string>() != "ok") failed.Add("usgs_ar");
        if (border.Result["status"]?.GetValue<string>() != "ok") failed.Add("usgs_oos");
        return new JsonObject
        {
            ["status"] = failed.Count == 0 ? "ok" : "partial_failure",
            ["feeds"] = feeds,
            ["failed_feeds"] = failed,
        };
    }

    private async Task CheckEarthquakeProximityAsync(JsonObject data, CancellationToken cancellationToken)
    {
        if (data["features"] is not JsonArray features) return;
        var state = await store.GetAlertStateAsync(cancellationToken);
        var alertedIds = ReadStringSet(state.AlertedEarthquakeIds);
        var sites = await facilities.GetAdminLocationsAsync(cancellationToken);
        var alerts = new List<EarthquakeAlert>();
        var triggeredIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var feature in features.OfType<JsonObject>())
        {
            var properties = feature["properties"] as JsonObject;
            var eventId = PropertyString(feature, "id", "") is { Length: > 0 } id
                ? id
                : $"{PropertyString(properties, "time", "0")}_{PropertyString(properties, "place", "unknown")}_{PropertyString(properties, "mag", "0")}";
            if (alertedIds.Contains(eventId)) continue;
            var magnitude = TryNumber(properties?["mag"], out var parsedMagnitude) ? parsedMagnitude : 0;
            var coordinates = (feature["geometry"] as JsonObject)?["coordinates"] as JsonArray;
            if (magnitude < 2.5 || coordinates is not { Count: >= 2 }
                || !TryNumber(coordinates[0], out var longitude) || !TryNumber(coordinates[1], out var latitude)) continue;
            var depth = coordinates.Count > 2 && TryNumber(coordinates[2], out var parsedDepth) ? parsedDepth : 0;
            var place = PropertyString(properties, "place", "Unknown");
            var time = FormatEarthquakeTime(properties?["time"]);
            var matched = false;
            foreach (var site in sites)
            {
                if (site.Latitude is not { } siteLatitude || site.Longitude is not { } siteLongitude
                    || !double.IsFinite(siteLatitude) || !double.IsFinite(siteLongitude)) continue;
                var distance = HaversineMiles(latitude, longitude, siteLatitude, siteLongitude);
                if (distance > 50) continue;
                alerts.Add(new EarthquakeAlert(
                    site.Name ?? "Unknown", site.LocationType ?? "General", Math.Round(distance, 1),
                    magnitude, place, depth, time));
                matched = true;
            }
            if (matched) triggeredIds.Add(eventId);
        }
        if (alerts.Count == 0) return;

        var settings = await integrationSettings.GetAsync(cancellationToken);
        var recipients = ParseRecipients(settings.RiskAlertRecipients);
        if (recipients.Length == 0) return;
        var result = await emailSender.SendPlainTextAsync(
            string.Join(", ", recipients),
            "NOC Alert: Earthquake Proximity Warning",
            BuildEarthquakeAlertBody(alerts),
            cancellationToken);
        if (result.Success)
        {
            alertedIds.UnionWith(triggeredIds);
            await store.SaveEarthquakeAlertIdsAsync(JsonSerializer.Serialize(alertedIds.OrderBy(value => value, StringComparer.Ordinal)), cancellationToken);
        }
    }

    private async Task CheckWildfireProximityAsync(CancellationToken cancellationToken)
    {
        var settings = await integrationSettings.GetAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(settings.NocNotifyEmail)) return;

        var json = await wildfires.GetActiveWildfiresJsonAsync(cancellationToken);
        var payload = JsonNode.Parse(json) as JsonObject;
        if (payload is null || PropertyString(payload["meta"] as JsonObject, "status", "") != "ok") return;
        var incidents = payload["incidents"] as JsonArray ?? [];
        var perimeters = payload["perimeters"] as JsonArray ?? [];
        if (incidents.Count == 0 && perimeters.Count == 0) return;

        var sites = await facilities.GetAdminLocationsAsync(cancellationToken);
        var state = await store.GetAlertStateAsync(cancellationToken);
        var alertedIds = ReadStringSet(state.AlertedWildfireIds);
        var proximityState = ReadJsonObject(state.WildfireProximityState);
        var perimeterNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var perimeterIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var closestSites = new Dictionary<string, List<ClosestSite>>(StringComparer.Ordinal);
        var matches = new List<WildfireAlert>();

        foreach (var perimeter in perimeters.OfType<JsonObject>())
        {
            var name = PropertyString(perimeter, "name", "Unknown Fire");
            var geometry = perimeter["geometry"];
            if (geometry is not JsonObject shape || !GeometryLines(shape).Any(line => line.Points.Length >= 2)) continue;
            var fireId = PropertyString(perimeter, "irwin_id", name).Trim();
            perimeterNames.Add(name.Trim());
            perimeterIds.Add(NormalizeFireId(fireId));
            var smallFire = IsSmallFire(perimeter);
            foreach (var site in sites)
            {
                if (!TrySite(site, out var longitude, out var latitude)) continue;
                var distance = DistanceToGeometryMiles(geometry, longitude, latitude);
                if (!double.IsFinite(distance) || smallFire && distance > 1.0) continue;
                AddClosest(closestSites, name, distance, site.Name ?? "Unknown");
                var alertKey = $"{fireId}:{site.Id}";
                var previous = proximityState[alertKey] as JsonObject;
                var lastAlertDistance = TryNumber(previous?["last_alert_distance"], out var priorDistance)
                    ? priorDistance
                    : (double?)null;
                if (distance <= 5.0 && (!alertedIds.Contains(alertKey)
                    || lastAlertDistance is null || lastAlertDistance.Value - distance >= 0.5))
                {
                    matches.Add(new WildfireAlert(alertKey, name, distance, perimeter, site.Name ?? "Unknown", alertedIds.Contains(alertKey)));
                }
                proximityState[alertKey] = new JsonObject
                {
                    ["last_seen_distance"] = Math.Round(distance, 3),
                    ["last_alert_distance"] = lastAlertDistance,
                };
            }
        }

        foreach (var incident in incidents.OfType<JsonObject>())
        {
            var name = PropertyString(incident, "name", "Unknown Fire");
            var fireIdForMatch = NormalizeFireId(PropertyString(incident, "irwin_id", ""));
            if (perimeterNames.Contains(name.Trim()) || fireIdForMatch.Length > 0 && perimeterIds.Contains(fireIdForMatch)) continue;
            if (!TryNumber(incident["lon"], out var longitude) || !TryNumber(incident["lat"], out var latitude)) continue;
            var fireId = PropertyString(incident, "irwin_id", PropertyString(incident, "unique_id", name)).Trim();
            var smallFire = IsSmallFire(incident);
            foreach (var site in sites)
            {
                if (!TrySite(site, out var siteLongitude, out var siteLatitude)) continue;
                var distance = HaversineMiles(latitude, longitude, siteLatitude, siteLongitude);
                if (smallFire && distance > 1.0) continue;
                AddClosest(closestSites, name, distance, site.Name ?? "Unknown");
                var alertKey = $"{fireId}:{site.Id}";
                var previous = proximityState[alertKey] as JsonObject;
                var lastAlertDistance = TryNumber(previous?["last_alert_distance"], out var priorDistance)
                    ? priorDistance
                    : (double?)null;
                if (distance <= 5.0 && (!alertedIds.Contains(alertKey)
                    || lastAlertDistance is null || lastAlertDistance.Value - distance >= 0.5))
                {
                    matches.Add(new WildfireAlert(alertKey, name, distance, incident, site.Name ?? "Unknown", alertedIds.Contains(alertKey)));
                }
                proximityState[alertKey] = new JsonObject
                {
                    ["last_seen_distance"] = Math.Round(distance, 3),
                    ["last_alert_distance"] = lastAlertDistance,
                };
            }
        }

        if (matches.Count == 0)
        {
            await store.SaveWildfireAlertStateAsync(
                JsonSerializer.Serialize(alertedIds.OrderBy(value => value, StringComparer.Ordinal)),
                proximityState.ToJsonString(), cancellationToken);
            return;
        }
        var send = await emailSender.SendPlainTextAsync(
            settings.NocNotifyEmail,
            "Wildfire Proximity Alert",
            BuildWildfireAlertBody(matches, closestSites),
            cancellationToken);
        if (send.Success)
        {
            foreach (var match in matches)
            {
                if (proximityState[match.AlertKey] is JsonObject current)
                {
                    current["last_alert_distance"] = Math.Round(match.DistanceMiles, 3);
                }
                alertedIds.Add(match.AlertKey);
            }
            await store.SaveWildfireAlertStateAsync(
                JsonSerializer.Serialize(alertedIds.OrderBy(value => value, StringComparer.Ordinal)),
                proximityState.ToJsonString(), cancellationToken);
        }
    }

    private static string BuildEarthquakeAlertBody(IReadOnlyList<EarthquakeAlert> alerts)
    {
        var lines = new List<string>
        {
            "NOC Intelligence Fusion Center - Earthquake Proximity Alert",
            new('=', 50),
            "",
            "Earthquake(s) detected within 50 miles of monitored sites:",
            "",
        };
        foreach (var alert in alerts)
        {
            lines.Add($"Site: {alert.Site} ({alert.SiteType})");
            lines.Add($"  Distance: {alert.DistanceMiles.ToString("F1", CultureInfo.InvariantCulture)} miles");
            lines.Add($"  Magnitude: M{alert.Magnitude.ToString("F1", CultureInfo.InvariantCulture)}");
            lines.Add($"  Location: {alert.Place}");
            lines.Add($"  Depth: {alert.DepthKilometers.ToString("F1", CultureInfo.InvariantCulture)} km");
            lines.Add($"  Time: {alert.Time}");
            lines.Add("");
        }
        lines.Add(new('-', 50));
        lines.Add($"Time: {FormatCentral(DateTimeOffset.UtcNow)}");
        lines.Add("");
        lines.Add("This is an automated alert from the NOC Intelligence Fusion Center.");
        return string.Join('\n', lines);
    }

    private static string BuildWildfireAlertBody(
        IReadOnlyList<WildfireAlert> alerts,
        IReadOnlyDictionary<string, List<ClosestSite>> closestSites)
    {
        var lines = new List<string>
        {
            "NOC WILDFIRE PROXIMITY ALERT",
            "",
            "Active WFCA wildfire activity detected within 5 miles of a monitored site.",
            "",
        };
        foreach (var alert in alerts)
        {
            var nearest = closestSites.GetValueOrDefault(alert.Name) ?? [];
            var closestText = string.Join(", ", nearest.Select(site =>
                $"{site.Name} ({site.DistanceMiles.ToString("F1", CultureInfo.InvariantCulture)} mi)"));
            if (closestText.Length == 0) closestText = "Unknown";
            var details = alert.Details;
            var contained = details["contained"] is { } containedValue ? ToText(containedValue) + "%" : "Unknown";
            var acres = details["acres"] ?? details["perimeter_acres"];
            lines.Add($"FIRE: {alert.Name}");
            lines.Add($"ALERT TYPE: {(alert.PreviouslyAlerted ? "WARNING - FIRE ENCROACHING" : "INITIAL PROXIMITY ALERT")}");
            lines.Add($"CLOSEST MONITORED SITE(S): {closestText}");
            lines.Add($"MONITORED SITE: {alert.Site}");
            lines.Add($"DISTANCE: {alert.DistanceMiles.ToString("F1", CultureInfo.InvariantCulture)} miles");
            lines.Add($"STATE: {PropertyString(details, "state", "Unknown")}");
            lines.Add($"COUNTY: {PropertyString(details, "county", "Unknown")}");
            lines.Add($"STARTED: {FormatProviderDate(details["started"])}");
            lines.Add($"ACRES: {(acres is null ? "Unknown" : ToText(acres))}");
            lines.Add($"MAPPED ACRES: {PropertyString(details, "perimeter_acres", "Unknown")}");
            lines.Add($"CONTAINMENT: {contained}");
            lines.Add($"CAUSE: {PropertyString(details, "cause", "Unknown")}");
            lines.Add($"PERIMETER UPDATED: {FormatProviderDate(details["perimeter_updated"])}");
            lines.Add($"MAP METHOD: {PropertyString(details, "map_method", "Unknown")}");
            lines.Add("");
        }
        return string.Join('\n', lines);
    }

    private static void AddClosest(
        IDictionary<string, List<ClosestSite>> closestSites,
        string fireName,
        double distance,
        string siteName)
    {
        if (!closestSites.TryGetValue(fireName, out var closest))
        {
            closestSites[fireName] = [new ClosestSite(distance, siteName)];
            return;
        }
        if (distance < closest[0].DistanceMiles - 0.1)
        {
            closestSites[fireName] = [new ClosestSite(distance, siteName)];
        }
        else if (Math.Abs(distance - closest[0].DistanceMiles) <= 0.1
                 && closest.All(site => site.Name != siteName))
        {
            closest.Add(new ClosestSite(distance, siteName));
        }
    }

    private static double DistanceToGeometryMiles(JsonNode? geometry, double longitude, double latitude)
    {
        if (RegionalGeoJsonViewportFilter.CoversPoint(geometry, longitude, latitude)) return 0;
        var nearest = double.PositiveInfinity;
        var longitudeScale = 69.172 * Math.Cos(latitude * Math.PI / 180.0);
        foreach (var (points, closeRing) in GeometryLines(geometry))
        {
            for (var index = 1; index < points.Length; index++)
            {
                nearest = Math.Min(nearest, SegmentDistanceMiles(
                    longitude, latitude, longitudeScale, points[index - 1], points[index]));
            }
            if (closeRing && points.Length > 2
                && (points[0].Longitude != points[^1].Longitude || points[0].Latitude != points[^1].Latitude))
            {
                nearest = Math.Min(nearest, SegmentDistanceMiles(
                    longitude, latitude, longitudeScale, points[^1], points[0]));
            }
        }
        return nearest;
    }

    private static IEnumerable<(MapPoint[] Points, bool CloseRing)> GeometryLines(JsonNode? geometry)
    {
        if (geometry is not JsonObject geometryObject) yield break;
        var type = PropertyString(geometryObject, "type", "");
        var coordinates = geometryObject["coordinates"];
        switch (type)
        {
            case "LineString":
                yield return (ReadLine(coordinates), false);
                break;
            case "MultiLineString":
                if (coordinates is JsonArray lines)
                    foreach (var line in lines) yield return (ReadLine(line), false);
                break;
            case "Polygon":
                if (coordinates is JsonArray rings)
                    foreach (var ring in rings) yield return (ReadLine(ring), true);
                break;
            case "MultiPolygon":
                if (coordinates is JsonArray polygons)
                    foreach (var polygon in polygons.OfType<JsonArray>())
                        foreach (var ring in polygon) yield return (ReadLine(ring), true);
                break;
            case "GeometryCollection":
                if (geometryObject["geometries"] is JsonArray geometries)
                    foreach (var item in geometries)
                        foreach (var line in GeometryLines(item)) yield return line;
                break;
        }
    }

    private static MapPoint[] ReadLine(JsonNode? value)
    {
        if (value is not JsonArray positions) return [];
        var result = new List<MapPoint>();
        foreach (var position in positions.OfType<JsonArray>())
        {
            if (position.Count >= 2 && TryNumber(position[0], out var longitude)
                && TryNumber(position[1], out var latitude))
            {
                result.Add(new MapPoint(longitude, latitude));
            }
        }
        return result.ToArray();
    }

    private static double SegmentDistanceMiles(
        double originLongitude,
        double originLatitude,
        double longitudeScale,
        MapPoint first,
        MapPoint second)
    {
        var x1 = (first.Longitude - originLongitude) * longitudeScale;
        var y1 = (first.Latitude - originLatitude) * 69.0;
        var x2 = (second.Longitude - originLongitude) * longitudeScale;
        var y2 = (second.Latitude - originLatitude) * 69.0;
        var dx = x2 - x1;
        var dy = y2 - y1;
        var length = dx * dx + dy * dy;
        var fraction = length == 0 ? 0 : Math.Clamp(-(x1 * dx + y1 * dy) / length, 0, 1);
        return Math.Sqrt(Math.Pow(x1 + fraction * dx, 2) + Math.Pow(y1 + fraction * dy, 2));
    }

    private static double HaversineMiles(double firstLatitude, double firstLongitude, double secondLatitude, double secondLongitude)
    {
        const double earthRadiusMiles = 3959;
        var firstLat = firstLatitude * Math.PI / 180;
        var secondLat = secondLatitude * Math.PI / 180;
        var deltaLat = (secondLatitude - firstLatitude) * Math.PI / 180;
        var deltaLon = (secondLongitude - firstLongitude) * Math.PI / 180;
        var a = Math.Pow(Math.Sin(deltaLat / 2), 2)
            + Math.Cos(firstLat) * Math.Cos(secondLat) * Math.Pow(Math.Sin(deltaLon / 2), 2);
        return earthRadiusMiles * 2 * Math.Asin(Math.Sqrt(Math.Clamp(a, 0, 1)));
    }

    private static bool TrySite(MonitoredLocationEntry site, out double longitude, out double latitude)
    {
        longitude = site.Longitude ?? 0;
        latitude = site.Latitude ?? 0;
        return site.Longitude is not null && site.Latitude is not null
            && double.IsFinite(longitude) && double.IsFinite(latitude);
    }

    private static bool IsSmallFire(JsonObject details) =>
        TryNumber(details["acres"], out var acres) && acres <= 1.0;

    private static string NormalizeFireId(string value) => value.Replace("{", "", StringComparison.Ordinal)
        .Replace("}", "", StringComparison.Ordinal).Trim().ToLowerInvariant();

    private static HashSet<string> ReadStringSet(string? json)
    {
        try
        {
            return JsonNode.Parse(json ?? "[]") is JsonArray values
                ? values.Where(value => value is not null).Select(ToText).ToHashSet(StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);
        }
        catch (JsonException)
        {
            return new HashSet<string>(StringComparer.Ordinal);
        }
    }

    private static JsonObject ReadJsonObject(string? json)
    {
        try
        {
            return JsonNode.Parse(json ?? "{}") as JsonObject ?? new JsonObject();
        }
        catch (JsonException)
        {
            return new JsonObject();
        }
    }

    private static string[] ParseRecipients(string? value) =>
        (value ?? "").Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal).ToArray();

    private static string FormatEarthquakeTime(JsonNode? value)
    {
        if (!TryNumber(value, out var milliseconds) || milliseconds == 0) return "Unknown";
        try
        {
            return FormatCentral(DateTimeOffset.FromUnixTimeMilliseconds((long)milliseconds));
        }
        catch (ArgumentOutOfRangeException)
        {
            return "Unknown";
        }
    }

    private static string FormatProviderDate(JsonNode? value)
    {
        if (value is null) return "Unknown";
        if (value is JsonValue textValue && textValue.TryGetValue<string>(out var text))
        {
            var timeMarker = text.IndexOf('T');
            var hasOffset = text.EndsWith('Z') || timeMarker >= 0
                && (text.LastIndexOf('+') > timeMarker || text.LastIndexOf('-') > timeMarker);
            if (hasOffset && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            {
                return FormatCentral(parsed);
            }
            if (DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var local))
            {
                var localCentral = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
                return FormatCentral(new DateTimeOffset(localCentral, CentralTimeZone.GetUtcOffset(localCentral)));
            }
            return text;
        }
        return TryNumber(value, out var milliseconds) ? FormatEarthquakeTime(JsonValue.Create(milliseconds)) : ToText(value);
    }

    private static string FormatCentral(DateTimeOffset value)
    {
        var local = TimeZoneInfo.ConvertTime(value, CentralTimeZone);
        return $"{local:yyyy-MM-dd HH:mm} {(CentralTimeZone.IsDaylightSavingTime(local) ? "CDT" : "CST")}";
    }

    private static string FormatCoordinate(double value) => value.ToString("R", CultureInfo.InvariantCulture);


    private async Task<JsonObject> SyncSpcOutlooksAsync(CancellationToken cancellationToken)
    {
        var results = await Task.WhenAll(SpcFeeds.Select(feed => FetchAndSaveFeedAsync(
            feed.Name, new Uri(feed.Url), "Mozilla/5.0 (NOC_Fusion_Center)", null, null, cancellationToken)));
        var feeds = new JsonObject();
        foreach (var result in results)
        {
            feeds[result.Name] = result.Summary;
        }
        return new JsonObject
        {
            ["status"] = results.All(result => result.Summary["status"]?.GetValue<string>() == "ok") ? "ok" : "partial_failure",
            ["feeds"] = feeds,
        };
    }

    private async Task<(JsonObject Result, JsonObject? Data)> SyncUsGsAsync(
        string scope,
        string feedName,
        CancellationToken cancellationToken)
    {
        var bounds = ParseBounds(scope == "ar" ? coverage.ArkansasBounds : coverage.WfsBounds);
        var startTime = DateTime.UtcNow.AddDays(-7).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var url = "https://earthquake.usgs.gov/fdsnws/event/1/query?format=geojson"
            + $"&starttime={startTime}&minmagnitude=2.0"
            + $"&minlatitude={FormatCoordinate(bounds.South)}&maxlatitude={FormatCoordinate(bounds.North)}"
            + $"&minlongitude={FormatCoordinate(bounds.West)}&maxlongitude={FormatCoordinate(bounds.East)}";
        var summary = new JsonObject
        {
            ["scope"] = scope,
            ["border_states"] = new JsonArray(BorderStateCodes.Select(code => (JsonNode?)JsonValue.Create(code)).ToArray()),
            ["buffer_miles"] = 50,
            ["precision"] = "projected_geometry",
        };
        var response = await FetchAndSaveFeedAsync(
            feedName,
            new Uri(url),
            "Mozilla/5.0 (NOC_Fusion_Center)",
            collection => FilterEarthquakes(collection, scope),
            summary.ToJsonString(),
            cancellationToken);
        return (response.Summary, response.Data);
    }

    private async Task<RegionalFeedFetch> FetchAndSaveFeedAsync(
        string feedName,
        Uri uri,
        string userAgent,
        Func<JsonObject, JsonObject>? transform,
        string? coverageSummaryJson,
        CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();
        int? httpStatus = null;
        var attemptedAt = DateTime.UtcNow;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/geo+json"));
            request.Headers.TryAddWithoutValidation("User-Agent", userAgent);
            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            httpStatus = (int)response.StatusCode;
            var durationMs = ElapsedMilliseconds(timer);
            if (!response.IsSuccessStatusCode)
            {
                var message = $"HTTP {httpStatus}";
                await store.RecordGeoJsonFailureAsync(feedName, message, httpStatus, durationMs, attemptedAt, cancellationToken);
                return new RegionalFeedFetch(feedName,
                    new JsonObject { ["status"] = "error", ["feed"] = feedName, ["message"] = message, ["http_status"] = httpStatus }, null);
            }

            var body = await ReadBodyAsync(response, cancellationToken);
            var collection = JsonNode.Parse(body) as JsonObject
                ?? throw new InvalidDataException("GeoJSON provider response was not an object.");
            if (collection["features"] is not JsonArray features)
            {
                throw new InvalidDataException("GeoJSON provider response did not contain a FeatureCollection.");
            }
            var data = transform is null ? collection : transform(collection);
            var count = (data["features"] as JsonArray)?.Count ?? 0;
            await store.SaveGeoJsonFeedAsync(
                feedName, data.ToJsonString(), count, durationMs, DateTime.UtcNow, coverageSummaryJson, cancellationToken);
            return new RegionalFeedFetch(feedName, new JsonObject
            {
                ["status"] = "ok", ["feed"] = feedName, ["feature_count"] = count, ["http_status"] = httpStatus,
            }, data);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            var durationMs = ElapsedMilliseconds(timer);
            await store.RecordGeoJsonFailureAsync(feedName, exception.Message, httpStatus, durationMs, attemptedAt, cancellationToken);
            return new RegionalFeedFetch(feedName, new JsonObject
            {
                ["status"] = "error", ["feed"] = feedName, ["message"] = exception.Message, ["http_status"] = httpStatus,
            }, null);
        }
    }

    private JsonObject FilterEarthquakes(JsonObject collection, string scope)
    {
        var features = new JsonArray();
        if (collection["features"] is JsonArray source)
        {
            foreach (var feature in source.OfType<JsonObject>())
            {
                var coordinates = (feature["geometry"] as JsonObject)?["coordinates"] as JsonArray;
                if (coordinates is not { Count: >= 2 }
                    || !TryNumber(coordinates[0], out var longitude)
                    || !TryNumber(coordinates[1], out var latitude))
                {
                    continue;
                }
                var included = scope == "ar"
                    ? coverage.IncludesArkansasPoint(longitude, latitude)
                    : coverage.IncludesBorderPoint(longitude, latitude);
                if (included)
                {
                    features.Add(feature.DeepClone());
                }
            }
        }
        var result = (JsonObject)collection.DeepClone();
        result["features"] = features;
        return result;
    }

    private NwsSplit SplitAlerts(JsonObject source, JsonArray features, DateTime nowUtc)
    {
        var arkansas = new JsonArray();
        var border = new JsonArray();
        var precisions = new Dictionary<string, int>(StringComparer.Ordinal);
        var hazards = new List<RegionalHazardSyncRow>();
        var references = new List<RegionalCapReference>();
        var arFeatures = new List<JsonObject>();
        var borderFeatures = new List<JsonObject>();

        foreach (var feature in features.OfType<JsonObject>())
        {
            var properties = feature["properties"] as JsonObject;
            var messageType = PropertyString(properties, "messageType", "Alert");
            foreach (var identifier in ReadReferences(properties))
            {
                references.Add(new RegionalCapReference(identifier,
                    messageType.Equals("cancel", StringComparison.OrdinalIgnoreCase) ? "cancelled" : "superseded"));
            }
            if (!IsUnexpired(properties, nowUtc))
            {
                continue;
            }
            var scope = GetAlertScope(feature, properties);
            if (scope is null)
            {
                continue;
            }
            var normalized = (JsonObject)feature.DeepClone();
            var normalizedProperties = normalized["properties"] as JsonObject ?? new JsonObject();
            normalizedProperties["noc_coverage_scope"] = scope.Value.Scope;
            normalizedProperties["noc_coverage_precision"] = scope.Value.Precision;
            normalized["properties"] = normalizedProperties;
            if (scope.Value.Scope == "arkansas")
            {
                arkansas.Add(normalized);
                arFeatures.Add(normalized);
            }
            else
            {
                border.Add(normalized);
                borderFeatures.Add(normalized);
            }
            precisions[scope.Value.Precision] = precisions.GetValueOrDefault(scope.Value.Precision) + 1;
            if (!messageType.Equals("cancel", StringComparison.OrdinalIgnoreCase))
            {
                hazards.Add(ToHazardRow(normalized, nowUtc));
            }
        }

        var precisionCounts = new JsonObject();
        foreach (var (precision, count) in precisions)
        {
            precisionCounts[precision] = count;
        }
        var summary = new JsonObject
        {
            ["source_feature_count"] = features.Count,
            ["arkansas_alert_count"] = arFeatures.Count,
            ["border_alert_count"] = borderFeatures.Count,
            ["coverage_precision_counts"] = precisionCounts,
            ["border_states"] = new JsonArray(BorderStateCodes.Select(code => (JsonNode?)JsonValue.Create(code)).ToArray()),
            ["buffer_miles"] = 50,
        };
        return new NwsSplit(
            new JsonObject { ["type"] = "FeatureCollection", ["features"] = arkansas },
            new JsonObject { ["type"] = "FeatureCollection", ["features"] = border },
            summary,
            arFeatures,
            borderFeatures,
            hazards,
            references.DistinctBy(item => (item.Identifier, item.Status)).ToArray());
    }

    private (string Scope, string Precision)? GetAlertScope(JsonObject feature, JsonObject? properties)
    {
        if (feature["geometry"] is JsonObject geometry
            && coverage.TryGetAlertGeometryScope(geometry, out var geometryScope))
        {
            return geometryScope is null ? null : (geometryScope, "alert_geometry");
        }

        var countyScope = CountyScope(ReadCountyFips(properties));
        if (countyScope is not null)
        {
            return (countyScope, "county_geocode");
        }

        var states = ReadStateCodes(properties);
        if (states.Contains("AR")) return ("arkansas", "state_fallback");
        if (states.Overlaps(BorderStateCodes)) return ("border", "state_fallback");
        if (feature["geometry"] is null) return ("border", "unresolved_state_fallback");
        return null;
    }

    private string? CountyScope(IEnumerable<string> fipsCodes)
    {
        var counties = countyGeometry.GetRegionalCounties();
        var matched = fipsCodes.Where(counties.ContainsKey).Select(fips => counties[fips]).ToArray();
        if (matched.Any(county => county.StateFips == "05")) return "arkansas";
        return matched.Any(county => BorderStateFips.Contains(county.StateFips)) ? "border" : null;
    }


    private static RegionalHazardSyncRow ToHazardRow(JsonObject feature, DateTime nowUtc)
    {
        var properties = feature["properties"] as JsonObject;
        var hazardId = StableAlertId(feature, properties);
        var eventName = PropertyString(properties, "event", "Unknown");
        var headline = PropertyString(properties, "headline", "");
        var expires = ReadUtcDate(properties?["expires"]);
        var references = ReadReferences(properties);
        var messageType = PropertyString(properties, "messageType", "Alert");
        return new RegionalHazardSyncRow(
            hazardId,
            eventName,
            PropertyString(properties, "severity", "Unknown"),
            !string.IsNullOrWhiteSpace(headline) ? headline : !string.IsNullOrWhiteSpace(eventName) ? eventName : "Weather Alert",
            PropertyString(properties, "description", ""),
            PropertyString(properties, "areaDesc", "Regional"),
            ReadUtcDate(properties?["sent"]),
            ReadUtcDate(properties?["effective"]),
            ReadUtcDate(properties?["onset"]),
            expires,
            ReadUtcDate(Truthy(properties?["ends"]) ? properties?["ends"] : properties?["eventEndingTime"]),
            messageType,
            JsonSerializer.Serialize(references),
            PropertyString(properties, "noc_coverage_scope", "border"),
            PropertyString(properties, "noc_coverage_precision", "alert_geometry"),
            expires is { } date && date <= nowUtc ? "expired" : "active");
    }

    private static string StableAlertId(JsonObject feature, JsonObject? properties)
    {
        var identifier = Truthy(properties?["id"]) ? properties!["id"] : feature["id"];
        if (Truthy(identifier)) return ToText(identifier);
        var fields = new[]
        {
            PropertyString(properties, "sender", ""), PropertyString(properties, "event", ""),
            PropertyString(properties, "sent", ""), PropertyString(properties, "areaDesc", ""),
            PropertyString(properties, "headline", ""),
        };
        return "nws-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('|', fields)))).ToLowerInvariant();
    }

    private static List<string> ReadReferences(JsonObject? properties)
    {
        var result = new List<string>();
        var references = properties?["references"];
        if (references is JsonArray array)
        {
            foreach (var item in array)
            {
                string? identifier = item is JsonObject reference
                    ? PropertyString(reference, "identifier", PropertyString(reference, "id", PropertyString(reference, "url", "")))
                    : ParseReferenceIdentifier(ToText(item));
                if (!string.IsNullOrWhiteSpace(identifier) && !result.Contains(identifier, StringComparer.Ordinal))
                {
                    result.Add(identifier);
                }
            }
        }
        else if (references is JsonValue value && value.TryGetValue<string>(out var text))
        {
            foreach (var part in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                var identifier = ParseReferenceIdentifier(part);
                if (!string.IsNullOrWhiteSpace(identifier) && !result.Contains(identifier, StringComparer.Ordinal))
                {
                    result.Add(identifier);
                }
            }
        }
        return result;
    }

    private static string ParseReferenceIdentifier(string reference)
    {
        var parts = reference.Split(',').Select(value => value.Trim()).ToArray();
        return parts.Length >= 2 ? parts[1] : parts.FirstOrDefault() ?? "";
    }

    private static HashSet<string> ReadCountyFips(JsonObject? properties)
    {
        var codes = new HashSet<string>(StringComparer.Ordinal);
        var geocode = properties?["geocode"] as JsonObject;
        foreach (var code in CodeValues(geocode?["SAME"]))
        {
            var digits = Digits(code);
            if (digits.Length >= 5) codes.Add(digits[^5..]);
        }
        foreach (var code in CodeValues(geocode?["UGC"]))
        {
            if (code.Length >= 6 && code[2] == 'C' && StateFipsByCode.TryGetValue(code[..2], out var state))
            {
                codes.Add(state + code[^3..]);
            }
        }
        return codes;
    }

    private static HashSet<string> ReadStateCodes(JsonObject? properties)
    {
        var states = new HashSet<string>(StringComparer.Ordinal);
        var geocode = properties?["geocode"] as JsonObject;
        foreach (var same in CodeValues(geocode?["SAME"]))
        {
            var digits = Digits(same);
            if (digits.Length >= 5 && StateCodeByFips.TryGetValue(digits[^5..^3], out var code)) states.Add(code);
        }
        foreach (var ugc in CodeValues(geocode?["UGC"]))
        {
            if (ugc.Length >= 2 && StateFipsByCode.ContainsKey(ugc[..2])) states.Add(ugc[..2]);
        }
        return states;
    }

    private static IEnumerable<string> CodeValues(JsonNode? value)
    {
        var values = value is JsonArray array
            ? array.Where(item => item is not null).Select(ToText)
            : (value is null ? "" : ToText(value)).Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return values.Select(code => code.Trim().ToUpperInvariant()).ToArray();
    }

    private static bool IsUnexpired(JsonObject? properties, DateTime nowUtc)
    {
        if (PropertyString(properties, "messageType", "Alert").Equals("cancel", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var expires = ReadUtcDate(properties?["expires"]);
        return expires is null || expires > nowUtc;
    }

    private static DateTime? ReadUtcDate(JsonNode? value)
    {
        var text = value is null ? null : ToText(value);
        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? parsed.UtcDateTime
            : null;
    }

    private static Wgs84Box ParseBounds(string value)
    {
        var numbers = value.Split(',').Take(4)
            .Select(part => double.Parse(part, NumberStyles.Float, CultureInfo.InvariantCulture)).ToArray();
        return new Wgs84Box(numbers[0], numbers[1], numbers[2], numbers[3]);
    }

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("GeoJSON provider response exceeded the configured size limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var count = await stream.ReadAsync(chunk, cancellationToken);
            if (count == 0) break;
            if (buffer.Length + count > MaxResponseBytes)
            {
                throw new InvalidDataException("GeoJSON provider response exceeded the configured size limit.");
            }
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    private string BuildNwsUserAgent()
    {
        var userAgent = nwsConfiguration.UserAgent;
        if (!string.IsNullOrWhiteSpace(nwsConfiguration.DefaultAdminEmail)
            && !userAgent.Contains(nwsConfiguration.DefaultAdminEmail, StringComparison.OrdinalIgnoreCase))
        {
            userAgent += $" ({nwsConfiguration.DefaultAdminEmail})";
        }
        return userAgent;
    }

    private static DateTime? ParseRetryAfter(RetryConditionHeaderValue? retryAfter, DateTime nowUtc) =>
        retryAfter?.Date?.UtcDateTime
        ?? (retryAfter?.Delta is { } delta ? nowUtc.Add(delta) : null);

    private static int ReadFeatureCount(string data)
    {
        try
        {
            return (JsonNode.Parse(data)?["features"] as JsonArray)?.Count ?? 0;
        }
        catch (JsonException)
        {
            return 0;
        }
    }

    private static int ElapsedMilliseconds(Stopwatch timer) =>
        (int)Math.Clamp(timer.ElapsedMilliseconds, 0, int.MaxValue);

    private static void AddDate(JsonObject result, string key, DateTime? value)
    {
        if (value is { } date)
        {
            result[key] = date.ToString("O", CultureInfo.InvariantCulture);
        }
    }

    private static bool TryNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out number) && double.IsFinite(number)) return true;
        if (value is JsonValue textValue && textValue.TryGetValue<string>(out var text)
            && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number) && double.IsFinite(number)) return true;
        number = 0;
        return false;
    }

    private static string ToText(JsonNode? value) => value switch
    {
        null => "None",
        JsonValue jsonValue when jsonValue.TryGetValue<string>(out var text) => text,
        JsonValue jsonValue when jsonValue.TryGetValue<bool>(out var boolean) => boolean ? "True" : "False",
        _ => value.ToJsonString(),
    };

    private static string PropertyString(JsonObject? properties, string key, string fallback) =>
        properties is not null && properties.TryGetPropertyValue(key, out var value) && value is not null
            ? ToText(value)
            : fallback;

    private static bool Truthy(JsonNode? value) => value switch
    {
        null => false,
        JsonValue jsonValue when jsonValue.TryGetValue<string>(out var text) => text.Length > 0,
        JsonValue jsonValue when jsonValue.TryGetValue<bool>(out var boolean) => boolean,
        JsonValue jsonValue when jsonValue.TryGetValue<double>(out var number) => number != 0,
        _ => true,
    };

    private static string Digits(string value) => new(value.Where(char.IsDigit).ToArray());

    private sealed record RegionalFeedFetch(string Name, JsonObject Summary, JsonObject? Data);
    private sealed record NwsSplit(
        JsonObject Arkansas,
        JsonObject Border,
        JsonObject Coverage,
        IReadOnlyList<JsonObject> ArkansasFeatures,
        IReadOnlyList<JsonObject> BorderFeatures,
        IReadOnlyList<RegionalHazardSyncRow> Hazards,
        IReadOnlyList<RegionalCapReference> References);
    private sealed record EarthquakeAlert(
        string Site,
        string SiteType,
        double DistanceMiles,
        double Magnitude,
        string Place,
        double DepthKilometers,
        string Time);
    private sealed record WildfireAlert(
        string AlertKey,
        string Name,
        double DistanceMiles,
        JsonObject Details,
        string Site,
        bool PreviouslyAlerted);
    private sealed record ClosestSite(double DistanceMiles, string Name);
    private readonly record struct MapPoint(double Longitude, double Latitude);
}
