using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Infrastructure.Integrations.Weather;

public sealed class WfcaWildfireSnapshotCache
{
    internal readonly SemaphoreSlim RefreshGate = new(1, 1);
    internal string? CachedJson;
    internal DateTime CachedUntilUtc;
    internal string? LastGoodDataJson;
    internal string? LastSuccessAt;
    internal string? LastError;
}

public sealed class WfcaWildfireClient(
    HttpClient httpClient,
    IFacilityDirectoryStore facilities,
    ArkansasFireCoverage coverage,
    WfcaWildfireSnapshotCache cache) : IRegionalWildfireProvider
{
    private const string WfsUrl = "https://prod-geoserver-lb.wfca.com/geoserver/wfs";
    private const int WfsPageSize = 2000;
    private const int MaxWfsPages = 20;
    private const int MaxWfsFeatures = WfsPageSize * MaxWfsPages;
    private const int MaxResponseBytes = 32 * 1024 * 1024;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    public async Task<string> GetActiveWildfiresJsonAsync(CancellationToken cancellationToken)
    {
        await cache.RefreshGate.WaitAsync(cancellationToken);
        try
        {
            if (cache.CachedJson is not null && cache.CachedUntilUtc > DateTime.UtcNow)
            {
                return cache.CachedJson;
            }
            try
            {
                var data = await FetchWildfireDataAsync(cancellationToken);
                cache.LastGoodDataJson = data.ToJsonString();
                cache.LastSuccessAt = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);
                cache.LastError = null;
                cache.CachedJson = BuildResponse(cache.LastGoodDataJson, "ok", cache.LastSuccessAt, null).ToJsonString();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                cache.LastError = exception.Message[..Math.Min(1000, exception.Message.Length)];
                var status = cache.LastSuccessAt is null ? "error" : "stale";
                cache.CachedJson = BuildResponse(cache.LastGoodDataJson, status, cache.LastSuccessAt, cache.LastError).ToJsonString();
            }
            cache.CachedUntilUtc = DateTime.UtcNow.Add(CacheDuration);
            return cache.CachedJson;
        }
        finally
        {
            cache.RefreshGate.Release();
        }
    }

    private async Task<JsonObject> FetchWildfireDataAsync(CancellationToken cancellationToken)
    {
        var incidentFeatures = await FetchWfsFeaturesAsync("WFCA:WFIGS_Incidents", coverage.WfsBounds, cancellationToken);
        var incidents = new List<FireInfo>();
        var firesById = new Dictionary<string, FireInfo>(StringComparer.Ordinal);
        foreach (var feature in incidentFeatures)
        {
            if (!TryReadFire(feature, out var fire))
            {
                continue;
            }
            incidents.Add(fire);
            var normalizedId = NormalizeFireId(fire.IrwinId);
            if (normalizedId.Length > 0)
            {
                firesById[normalizedId] = fire;
            }
        }

        IReadOnlyList<JsonElement> perimeterFeatures;
        try
        {
            perimeterFeatures = await FetchWfsFeaturesAsync("WFCA:WFIGS_Perimeters", coverage.WfsBounds, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            perimeterFeatures = [];
        }
        var perimeters = BuildPerimeters(perimeterFeatures, firesById);

        IReadOnlyList<JsonElement> footprintFeatures = [];
        if (incidents.Count > 0)
        {
            try
            {
                footprintFeatures = await FetchWfsFeaturesAsync("WFCA:FIRMS_Footprints", coverage.WfsBounds, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                footprintFeatures = [];
            }
        }
        var footprints = BuildFootprints(footprintFeatures, firesById, perimeters);

        await SuppressDistantSmallFiresAsync(incidents, perimeters, footprints, cancellationToken);
        return new JsonObject
        {
            ["incidents"] = new JsonArray(incidents.Select(fire => (JsonNode?)fire.ToJson()).ToArray()),
            ["perimeters"] = new JsonArray(perimeters.Values.Select(item => (JsonNode?)item.ToPerimeterJson()).ToArray()),
            ["footprints"] = new JsonArray(footprints.Values.Select(item => (JsonNode?)item.ToJson()).ToArray()),
        };
    }

    private async Task<IReadOnlyList<JsonElement>> FetchWfsFeaturesAsync(
        string layerName,
        string bbox,
        CancellationToken cancellationToken)
    {
        var features = new List<JsonElement>();
        long offset = 0;
        for (var page = 0; page < MaxWfsPages; page++)
        {
            var sortBy = layerName.EndsWith("Incidents", StringComparison.Ordinal)
                ? "objectid A"
                : layerName.EndsWith("Footprints", StringComparison.Ordinal) ? "irwinid A" : "attr_irwinid A";
            var query = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["service"] = "WFS",
                ["version"] = "2.0.0",
                ["request"] = "GetFeature",
                ["typeNames"] = layerName,
                ["outputFormat"] = "application/json",
                ["srsName"] = "EPSG:4326",
                ["bbox"] = bbox,
                ["count"] = WfsPageSize.ToString(CultureInfo.InvariantCulture),
                ["sortBy"] = sortBy,
                ["startIndex"] = offset.ToString(CultureInfo.InvariantCulture),
            };
            var queryString = string.Join("&", query.Select(pair =>
                $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
            var uri = new Uri($"{WfsUrl}?{queryString}", UriKind.Absolute);
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"WFCA WFS returned HTTP {(int)response.StatusCode}.");
            }
            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
            {
                throw new InvalidDataException("WFCA WFS page exceeded the response size limit.");
            }
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var read = await stream.ReadAsync(chunk, cancellationToken);
                if (read == 0)
                {
                    break;
                }
                if (buffer.Length + read > MaxResponseBytes)
                {
                    throw new InvalidDataException("WFCA WFS page exceeded the response size limit.");
                }
                buffer.Write(chunk, 0, read);
            }
            using var document = JsonDocument.Parse(buffer.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object
                || !document.RootElement.TryGetProperty("features", out var pageFeatures)
                || pageFeatures.ValueKind != JsonValueKind.Array)
            {
                throw new InvalidDataException($"WFCA WFS returned an invalid feature collection for {layerName}.");
            }
            var pageCount = pageFeatures.GetArrayLength();
            foreach (var feature in pageFeatures.EnumerateArray())
            {
                features.Add(feature.Clone());
            }
            if (features.Count > MaxWfsFeatures)
            {
                throw new InvalidDataException("WFCA WFS feature limit was exceeded.");
            }
            var matched = ReadMatchedCount(document.RootElement);
            if (pageCount == 0 || (matched is { } total && features.Count >= total))
            {
                break;
            }
            if (matched is null && pageCount < WfsPageSize)
            {
                break;
            }
            if (page == MaxWfsPages - 1)
            {
                throw new InvalidDataException("WFCA WFS pagination limit was exceeded.");
            }
            offset += pageCount;
        }
        return features;
    }

    private bool TryReadFire(JsonElement feature, out FireInfo fire)
    {
        fire = default!;
        var properties = GetObject(feature, "properties");
        if (!string.Equals(ReadText(properties, "incidenttypecategory"), "WF", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var stale = ReadText(properties, "stale_flag");
        if (stale is not null && stale.Trim().ToLowerInvariant() is "true" or "1" or "yes")
        {
            return false;
        }
        var contained = ReadNumber(properties, "percentcontained");
        if (contained is >= 100)
        {
            return false;
        }

        var coordinates = GetElement(GetObject(feature, "geometry"), "coordinates");
        double? longitude = null;
        double? latitude = null;
        if (coordinates.ValueKind == JsonValueKind.Array && coordinates.GetArrayLength() >= 2)
        {
            var position = coordinates.EnumerateArray();
            if (position.MoveNext()) longitude = Number(position.Current);
            if (position.MoveNext()) latitude = Number(position.Current);
        }
        longitude ??= ReadNumber(properties, "initiallongitude");
        latitude ??= ReadNumber(properties, "initiallatitude");
        if (longitude is null || latitude is null || !coverage.IncludesPoint(longitude.Value, latitude.Value))
        {
            return false;
        }

        var acres = ReadNumber(properties, "wfca_reportedacres");
        if (acres is null or <= 0)
        {
            acres = ReadNumber(properties, "discoveryacres") ?? 0;
        }
        var state = ReadText(properties, "poostate") ?? "Unknown";
        if (state.StartsWith("US-", StringComparison.Ordinal))
        {
            state = state[3..];
        }
        fire = new FireInfo(
            FirstTruthy(ReadText(properties, "incidentname"), "Unnamed") ?? "Unnamed",
            state,
            Math.Round(acres.Value, 2),
            contained,
            longitude.Value,
            latitude.Value,
            ReadText(properties, "firediscoverydatetime"),
            ReadText(properties, "modifiedondatetime_dt"),
            ReadText(properties, "firecause"),
            ReadText(properties, "poocounty"),
            ReadText(properties, "irwinid"),
            ReadText(properties, "uniquefireidentifier"));
        return true;
    }

    private static Dictionary<string, GeometryGroup> BuildPerimeters(
        IReadOnlyList<JsonElement> features,
        IReadOnlyDictionary<string, FireInfo> firesById)
    {
        var perimeters = new Dictionary<string, GeometryGroup>(StringComparer.Ordinal);
        foreach (var feature in features)
        {
            var properties = GetObject(feature, "properties");
            var id = NormalizeFireId(ReadText(properties, "attr_irwinid"));
            if (id.Length == 0 || !firesById.TryGetValue(id, out var fire))
            {
                continue;
            }
            var geometry = ReadNode(GetElement(feature, "geometry"));
            if (geometry is null)
            {
                continue;
            }
            if (!perimeters.TryGetValue(id, out var perimeter))
            {
                perimeter = new GeometryGroup(fire);
                perimeters.Add(id, perimeter);
            }
            perimeter.Geometries.Add(geometry);
            var updated = FirstTruthy(ReadText(properties, "poly_datecurrent"), ReadText(properties, "attr_modifiedondatetime_dt"));
            if (updated is not null && (perimeter.Updated is null
                || string.CompareOrdinal(updated, perimeter.Updated) > 0))
            {
                perimeter.Updated = updated;
            }
        }
        return perimeters;
    }

    private static Dictionary<string, FootprintGroup> BuildFootprints(
        IReadOnlyList<JsonElement> features,
        IReadOnlyDictionary<string, FireInfo> firesById,
        IReadOnlyDictionary<string, GeometryGroup> perimeters)
    {
        var footprints = new Dictionary<string, FootprintGroup>(StringComparer.Ordinal);
        foreach (var feature in features)
        {
            var properties = GetObject(feature, "properties");
            var id = NormalizeFireId(ReadText(properties, "irwinid"));
            if (id.Length == 0 || !firesById.TryGetValue(id, out var fire) || perimeters.ContainsKey(id))
            {
                continue;
            }
            var ageBucket = (ReadText(properties, "age_bucket") ?? "").ToLowerInvariant();
            var hoursSince = ReadNumber(properties, "hours_since");
            if (ageBucket is not ("newest" or "recent") || (hoursSince is not null && hoursSince > 48))
            {
                continue;
            }
            var geometry = ReadNode(GetElement(feature, "geometry"));
            if (geometry is null)
            {
                continue;
            }
            if (!footprints.TryGetValue(id, out var footprint))
            {
                footprint = new FootprintGroup(fire);
                footprints.Add(id, footprint);
            }
            footprint.Geometries.Add(geometry);
            footprint.AreaAcres = Math.Max(footprint.AreaAcres, ReadNumber(properties, "area_acres") ?? 0);
            footprint.DetectionCount += (int)(ReadNumber(properties, "detection_count") ?? 0);
            var sensor = ReadText(properties, "sensor");
            if (!string.IsNullOrEmpty(sensor))
            {
                footprint.Sensors.Add(sensor);
            }
            var epoch = ReadNumber(properties, "latest_acq_epoch");
            if (epoch is not null && (footprint.UpdatedEpoch is null || epoch > footprint.UpdatedEpoch))
            {
                footprint.UpdatedEpoch = epoch;
            }
            var wfcaUpdated = ReadText(properties, "wfca_timestamp");
            if (wfcaUpdated is not null && (footprint.WfcaUpdated is null
                || string.CompareOrdinal(wfcaUpdated, footprint.WfcaUpdated) > 0))
            {
                footprint.WfcaUpdated = wfcaUpdated;
            }
        }
        return footprints;
    }

    private async Task SuppressDistantSmallFiresAsync(
        List<FireInfo> fires,
        Dictionary<string, GeometryGroup> perimeters,
        Dictionary<string, FootprintGroup> footprints,
        CancellationToken cancellationToken)
    {
        if (!fires.Any(fire => fire.Acres <= 1))
        {
            return;
        }
        IReadOnlyList<MonitoredLocationEntry> locations;
        try
        {
            locations = await facilities.GetAdminLocationsAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return;
        }
        var sites = locations
            .Where(location => location.Latitude is { } latitude && double.IsFinite(latitude)
                && location.Longitude is { } longitude && double.IsFinite(longitude))
            .Select(location => (Longitude: location.Longitude!.Value, Latitude: location.Latitude!.Value))
            .ToArray();
        if (sites.Length == 0)
        {
            return;
        }

        var retained = new List<FireInfo>();
        var retainedIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var fire in fires)
        {
            var id = NormalizeFireId(fire.IrwinId);
            if (fire.Acres <= 1 && !IsWithinOneMile(fire, id, perimeters, sites))
            {
                continue;
            }
            retained.Add(fire);
            if (id.Length > 0)
            {
                retainedIds.Add(id);
            }
        }
        fires.Clear();
        fires.AddRange(retained);
        foreach (var id in perimeters.Keys.Where(id => !retainedIds.Contains(id)).ToArray())
        {
            perimeters.Remove(id);
        }
        foreach (var id in footprints.Keys.Where(id => !retainedIds.Contains(id)).ToArray())
        {
            footprints.Remove(id);
        }
    }

    private static bool IsWithinOneMile(
        FireInfo fire,
        string id,
        IReadOnlyDictionary<string, GeometryGroup> perimeters,
        IReadOnlyList<(double Longitude, double Latitude)> sites)
    {
        if (id.Length > 0 && perimeters.TryGetValue(id, out var perimeter))
        {
            var distances = perimeter.Geometries
                .Select(GeometrySiteDistanceMiles)
                .Where(distance => distance is not null)
                .Select(distance => distance!)
                .ToArray();
            if (distances.Length > 0)
            {
                return sites.Any(site => distances.Any(distance => distance(site.Longitude, site.Latitude) <= 1));
            }
        }
        return sites.Any(site => HaversineMiles(fire.Longitude, fire.Latitude, site.Longitude, site.Latitude) <= 1);
    }

    private static Func<double, double, double>? GeometrySiteDistanceMiles(JsonNode geometry)
    {
        var sequences = new List<(List<Coordinate> Points, bool CloseRing)>();
        var polygons = new List<List<List<Coordinate>>>();
        if (!CollectGeometry(geometry, sequences, polygons) || sequences.Count == 0)
        {
            return null;
        }
        var minLatitude = sequences.SelectMany(sequence => sequence.Points).Min(point => point.Latitude);
        var maxLatitude = sequences.SelectMany(sequence => sequence.Points).Max(point => point.Latitude);
        var referenceLatitude = (minLatitude + maxLatitude) / 2;
        var milesPerLongitudeDegree = 69.172 * Math.Cos(referenceLatitude * Math.PI / 180.0);
        var projectedSequences = sequences.Select(sequence => (
            Points: sequence.Points.Select(point => new PlanarPoint(
                point.Longitude * milesPerLongitudeDegree, point.Latitude * 69.0)).ToArray(),
            sequence.CloseRing)).ToArray();

        return (longitude, latitude) =>
        {
            var point = new PlanarPoint(longitude * milesPerLongitudeDegree, latitude * 69.0);
            if (polygons.Any(polygon => ContainsPoint(polygon, longitude, latitude)))
            {
                return 0;
            }
            var closest = double.PositiveInfinity;
            foreach (var sequence in projectedSequences)
            {
                foreach (var vertex in sequence.Points)
                {
                    closest = Math.Min(closest, Distance(point, vertex));
                }
                for (var index = 1; index < sequence.Points.Length; index++)
                {
                    closest = Math.Min(closest, DistanceToSegment(point, sequence.Points[index - 1], sequence.Points[index]));
                }
                if (sequence.CloseRing && sequence.Points.Length > 2)
                {
                    closest = Math.Min(closest, DistanceToSegment(point, sequence.Points[^1], sequence.Points[0]));
                }
            }
            return closest;
        };
    }

    private static bool CollectGeometry(
        JsonNode geometry,
        List<(List<Coordinate> Points, bool CloseRing)> sequences,
        List<List<List<Coordinate>>> polygons)
    {
        if (geometry is not JsonObject objectGeometry)
        {
            return false;
        }
        var type = ReadNodeText(objectGeometry["type"]);
        var coordinates = objectGeometry["coordinates"];
        switch (type)
        {
            case "Point":
                return AddSequence(coordinates, false, sequences);
            case "MultiPoint":
                return AddManySequences(coordinates, false, sequences);
            case "LineString":
                return AddSequence(coordinates, false, sequences);
            case "MultiLineString":
                return AddManySequences(coordinates, false, sequences);
            case "Polygon":
                return AddPolygon(coordinates, sequences, polygons);
            case "MultiPolygon":
                if (coordinates is not JsonArray polygonList) return false;
                foreach (var polygon in polygonList)
                {
                    if (!AddPolygon(polygon, sequences, polygons)) return false;
                }
                return true;
            case "GeometryCollection":
                if (objectGeometry["geometries"] is not JsonArray geometries) return false;
                foreach (var child in geometries)
                {
                    if (child is not JsonObject childGeometry || !CollectGeometry(childGeometry, sequences, polygons))
                    {
                        return false;
                    }
                }
                return true;
            default:
                return false;
        }
    }

    private static bool AddPolygon(
        JsonNode? rawRings,
        List<(List<Coordinate> Points, bool CloseRing)> sequences,
        List<List<List<Coordinate>>> polygons)
    {
        if (rawRings is not JsonArray rings) return false;
        var polygon = new List<List<Coordinate>>();
        foreach (var ring in rings)
        {
            if (!ReadCoordinates(ring, out var points)) return false;
            polygon.Add(points);
            sequences.Add((points, true));
        }
        if (polygon.Count == 0) return false;
        polygons.Add(polygon);
        return true;
    }

    private static bool AddManySequences(
        JsonNode? rawLines,
        bool closeRing,
        List<(List<Coordinate> Points, bool CloseRing)> sequences)
    {
        if (rawLines is not JsonArray lines) return false;
        foreach (var line in lines)
        {
            if (!AddSequence(line, closeRing, sequences)) return false;
        }
        return true;
    }

    private static bool AddSequence(
        JsonNode? rawPoints,
        bool closeRing,
        List<(List<Coordinate> Points, bool CloseRing)> sequences)
    {
        if (!ReadCoordinates(rawPoints, out var points)) return false;
        sequences.Add((points, closeRing));
        return true;
    }

    private static bool ReadCoordinates(JsonNode? rawPoints, out List<Coordinate> points)
    {
        points = [];
        if (rawPoints is not JsonArray positions) return false;
        foreach (var position in positions)
        {
            if (position is not JsonArray pair || pair.Count < 2
                || !TryReadNumber(pair[0], out var longitude)
                || !TryReadNumber(pair[1], out var latitude))
            {
                return false;
            }
            points.Add(new Coordinate(longitude, latitude));
        }
        return true;
    }

    private static bool TryReadNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out number) && double.IsFinite(number))
        {
            return true;
        }
        if (value is JsonValue textValue && textValue.TryGetValue<string>(out var text)
            && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
            && double.IsFinite(number))
        {
            return true;
        }
        number = 0;
        return false;
    }

    private static string? ReadNodeText(JsonNode? value) =>
        value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text) ? text : null;

    private static bool ContainsPoint(List<List<Coordinate>> polygon, double longitude, double latitude)
    {
        if (polygon.Count == 0 || PointInRing(polygon[0], longitude, latitude) < 0) return false;
        for (var index = 1; index < polygon.Count; index++)
        {
            if (PointInRing(polygon[index], longitude, latitude) >= 0) return false;
        }
        return true;
    }

    private static int PointInRing(IReadOnlyList<Coordinate> ring, double longitude, double latitude)
    {
        if (ring.Count < 3) return -1;
        var inside = false;
        for (var index = 0; index < ring.Count; index++)
        {
            var current = ring[index];
            var previous = ring[(index + ring.Count - 1) % ring.Count];
            if (IsPointOnSegment(previous.Longitude, previous.Latitude, current.Longitude, current.Latitude, longitude, latitude))
            {
                return 0;
            }
            if ((current.Latitude > latitude) != (previous.Latitude > latitude)
                && longitude < (previous.Longitude - current.Longitude) * (latitude - current.Latitude)
                    / (previous.Latitude - current.Latitude) + current.Longitude)
            {
                inside = !inside;
            }
        }
        return inside ? 1 : -1;
    }

    private static double HaversineMiles(double longitude1, double latitude1, double longitude2, double latitude2)
    {
        const double radiusMiles = 3958.7613;
        var lat1 = latitude1 * Math.PI / 180.0;
        var lat2 = latitude2 * Math.PI / 180.0;
        var deltaLat = lat2 - lat1;
        var deltaLon = (longitude2 - longitude1) * Math.PI / 180.0;
        var a = Math.Pow(Math.Sin(deltaLat / 2), 2)
            + Math.Cos(lat1) * Math.Cos(lat2) * Math.Pow(Math.Sin(deltaLon / 2), 2);
        return radiusMiles * 2 * Math.Asin(Math.Min(1, Math.Sqrt(a)));
    }

    private static double Distance(PlanarPoint first, PlanarPoint second) =>
        Math.Sqrt(Math.Pow(first.X - second.X, 2) + Math.Pow(first.Y - second.Y, 2));

    private static double DistanceToSegment(PlanarPoint point, PlanarPoint start, PlanarPoint end)
    {
        var deltaX = end.X - start.X;
        var deltaY = end.Y - start.Y;
        var lengthSquared = deltaX * deltaX + deltaY * deltaY;
        if (lengthSquared == 0) return Distance(point, start);
        var fraction = Math.Clamp(((point.X - start.X) * deltaX + (point.Y - start.Y) * deltaY) / lengthSquared, 0, 1);
        return Distance(point, new PlanarPoint(start.X + fraction * deltaX, start.Y + fraction * deltaY));
    }

    private static bool IsPointOnSegment(
        double startX,
        double startY,
        double endX,
        double endY,
        double pointX,
        double pointY)
    {
        const double tolerance = 1e-10;
        var cross = (pointY - startY) * (endX - startX) - (pointX - startX) * (endY - startY);
        return Math.Abs(cross) <= tolerance
            && pointX >= Math.Min(startX, endX) - tolerance
            && pointX <= Math.Max(startX, endX) + tolerance
            && pointY >= Math.Min(startY, endY) - tolerance
            && pointY <= Math.Max(startY, endY) + tolerance;
    }

    private static string NormalizeFireId(string? value) =>
        (value ?? "").Trim().Trim('{', '}').ToLowerInvariant();

    private static string? ReadText(JsonElement parent, string property) =>
        ReadText(GetElement(parent, property));

    private static string? ReadText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        JsonValueKind.Object or JsonValueKind.Array => value.GetRawText(),
        _ => null,
    };

    private static JsonElement GetObject(JsonElement parent, string property) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(property, out var value)
            && value.ValueKind == JsonValueKind.Object ? value : default;

    private static JsonElement GetElement(JsonElement parent, string property) =>
        parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(property, out var value) ? value : default;

    private static JsonNode? ReadNode(JsonElement value) =>
        value.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? JsonNode.Parse(value.GetRawText()) : null;

    private static double? ReadNumber(JsonElement parent, string property) => Number(GetElement(parent, property));

    private static double? Number(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Number && value.TryGetDouble(out var number) && double.IsFinite(number))
        {
            return number;
        }
        if (value.ValueKind == JsonValueKind.String
            && double.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number)
            && double.IsFinite(number))
        {
            return number;
        }
        return null;
    }

    private static string? FirstTruthy(string? value, string? fallback) =>
        string.IsNullOrEmpty(value) ? fallback : value;

    private static long? ReadMatchedCount(JsonElement root)
    {
        var value = GetElement(root, "numberMatched");
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number)) return number;
        return value.ValueKind == JsonValueKind.String
            && long.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out number)
                ? number
                : null;
    }

    private static string? FormatIsoEpoch(double? seconds)
    {
        if (seconds is null || !double.IsFinite(seconds.Value)) return null;
        try
        {
            return DateTimeOffset.FromUnixTimeSeconds((long)seconds.Value)
                .ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff+00:00", CultureInfo.InvariantCulture);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static JsonObject BuildResponse(string? dataJson, string status, string? lastSuccessAt, string? error)
    {
        var data = dataJson is null
            ? new JsonObject
            {
                ["incidents"] = new JsonArray(),
                ["perimeters"] = new JsonArray(),
                ["footprints"] = new JsonArray(),
            }
            : JsonNode.Parse(dataJson) as JsonObject ?? new JsonObject();
        data["meta"] = new JsonObject
        {
            ["status"] = status,
            ["last_success_at"] = lastSuccessAt,
            ["last_error"] = error,
            ["coverage_miles"] = 50,
        };
        return data;
    }

    private readonly record struct Coordinate(double Longitude, double Latitude);
    private readonly record struct PlanarPoint(double X, double Y);

    private sealed record FireInfo(
        string Name,
        string State,
        double Acres,
        double? Contained,
        double Longitude,
        double Latitude,
        string? Started,
        string? Updated,
        string? Cause,
        string? County,
        string? IrwinId,
        string? UniqueId)
    {
        public JsonObject ToJson() => new()
        {
            ["name"] = Name,
            ["state"] = State,
            ["acres"] = Acres,
            ["contained"] = Contained,
            ["lon"] = Longitude,
            ["lat"] = Latitude,
            ["started"] = Started,
            ["updated"] = Updated,
            ["cause"] = Cause,
            ["county"] = County,
            ["irwin_id"] = IrwinId,
            ["unique_id"] = UniqueId,
            ["source"] = "WFCA",
            ["color"] = new JsonArray(220, 20, 60, 230),
        };
    }

    private class GeometryGroup(FireInfo fire)
    {
        public FireInfo Fire { get; } = fire;
        public List<JsonNode> Geometries { get; } = [];
        public string? Updated { get; set; }

        public JsonObject ToPerimeterJson() => new()
        {
            ["geometry"] = Combine(),
            ["name"] = Fire.Name,
            ["irwin_id"] = Fire.IrwinId,
            ["acres"] = Fire.Acres,
            ["perimeter_updated"] = Updated,
            ["map_method"] = "WFCA Fire Map",
            ["contained"] = Fire.Contained,
            ["started"] = Fire.Started,
            ["cause"] = Fire.Cause,
            ["state"] = Fire.State,
            ["county"] = Fire.County,
            ["source"] = "WFCA",
        };

        public JsonNode? Combine()
        {
            if (Geometries.Count == 0) return null;
            if (Geometries.Count == 1) return Geometries[0].DeepClone();
            // shortcut: polygon shards are kept as a MultiPolygon; use a GIS dissolve when operators need overlaps merged.
            var polygons = new JsonArray();
            foreach (var geometry in Geometries)
            {
                if (geometry is not JsonObject polygon) return Collection();
                var type = ReadNodeText(polygon["type"]);
                if (type == "Polygon" && polygon["coordinates"] is JsonArray coordinates)
                {
                    polygons.Add(coordinates.DeepClone());
                }
                else if (type == "MultiPolygon" && polygon["coordinates"] is JsonArray multi)
                {
                    foreach (var part in multi) polygons.Add(part?.DeepClone());
                }
                else
                {
                    return Collection();
                }
            }
            return new JsonObject { ["type"] = "MultiPolygon", ["coordinates"] = polygons };
        }

        private JsonObject Collection() => new()
        {
            ["type"] = "GeometryCollection",
            ["geometries"] = new JsonArray(Geometries.Select(geometry => geometry.DeepClone()).ToArray()),
        };
    }

    private sealed class FootprintGroup(FireInfo fire) : GeometryGroup(fire)
    {
        public double AreaAcres { get; set; }
        public int DetectionCount { get; set; }
        public SortedSet<string> Sensors { get; } = new(StringComparer.Ordinal);
        public double? UpdatedEpoch { get; set; }
        public string? WfcaUpdated { get; set; }

        public JsonObject ToJson() => new()
        {
            ["geometry"] = Combine(),
            ["name"] = Fire.Name,
            ["irwin_id"] = Fire.IrwinId,
            ["area_acres"] = Math.Round(AreaAcres, 1),
            ["detection_count"] = DetectionCount,
            ["sensors"] = new JsonArray(Sensors.Select(sensor => (JsonNode?)JsonValue.Create(sensor)).ToArray()),
            ["updated"] = FormatIsoEpoch(UpdatedEpoch) ?? WfcaUpdated,
            ["source"] = "WFCA FIRMS satellite footprint",
        };
    }
}
