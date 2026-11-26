using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;

namespace NocIfc.Infrastructure.Integrations.Weather;

public sealed class ArkansasFireCoverage : IRegionalCountyGeometryProvider
{
    private const double BufferMiles = 50.0;
    private const double MilesToMeters = 1609.344;
    private const double SemiMajorMeters = 6_378_137.0;
    private const double Flattening = 1 / 298.257223563;
    private const double DegreesToRadians = Math.PI / 180.0;
    private static readonly Lazy<ArkansasFireCoverage> CachedCoverage = new(LoadBundled);
    private readonly Polygon[] _arkansasCounties;
    private readonly IReadOnlyDictionary<string, RegionalCountyGeometry> _regionalCounties;
    private readonly double _centerLongitude;
    private readonly double _centerLatitude;
    private readonly double _minLongitude;
    private readonly double _minLatitude;
    private readonly double _maxLongitude;
    private readonly double _maxLatitude;
    private readonly double _bufferMinLongitude;
    private readonly double _bufferMinLatitude;
    private readonly double _bufferMaxLongitude;
    private readonly double _bufferMaxLatitude;

    private ArkansasFireCoverage(
        Polygon[] arkansasCounties,
        IReadOnlyDictionary<string, RegionalCountyGeometry> regionalCounties,
        double minLongitude,
        double minLatitude,
        double maxLongitude,
        double maxLatitude)
    {
        _arkansasCounties = arkansasCounties;
        _regionalCounties = regionalCounties;
        _centerLongitude = (minLongitude + maxLongitude) / 2;
        _centerLatitude = (minLatitude + maxLatitude) / 2;
        _minLongitude = minLongitude;
        _minLatitude = minLatitude;
        _maxLongitude = maxLongitude;
        _maxLatitude = maxLatitude;
        foreach (var county in _arkansasCounties)
        {
            foreach (var ring in county.Rings)
            {
                ring.Projected = ring.Points.Select(Project).ToArray();
            }
        }

        var latitudeMargin = BufferMiles / 68.0;
        var maximumAbsoluteLatitude = Math.Max(Math.Abs(minLatitude - latitudeMargin), Math.Abs(maxLatitude + latitudeMargin));
        var longitudeMargin = BufferMiles / (68.0 * Math.Cos(maximumAbsoluteLatitude * DegreesToRadians));
        _bufferMinLongitude = minLongitude - longitudeMargin;
        _bufferMinLatitude = minLatitude - latitudeMargin;
        _bufferMaxLongitude = maxLongitude + longitudeMargin;
        _bufferMaxLatitude = maxLatitude + latitudeMargin;
        ArkansasBounds = string.Join(',',
            minLongitude.ToString("F5", CultureInfo.InvariantCulture),
            minLatitude.ToString("F5", CultureInfo.InvariantCulture),
            maxLongitude.ToString("F5", CultureInfo.InvariantCulture),
            maxLatitude.ToString("F5", CultureInfo.InvariantCulture),
            "EPSG:4326");
        WfsBounds = string.Join(',',
            (minLongitude - longitudeMargin).ToString("F5", CultureInfo.InvariantCulture),
            (minLatitude - latitudeMargin).ToString("F5", CultureInfo.InvariantCulture),
            (maxLongitude + longitudeMargin).ToString("F5", CultureInfo.InvariantCulture),
            (maxLatitude + latitudeMargin).ToString("F5", CultureInfo.InvariantCulture),
            "EPSG:4326");
    }

    public string WfsBounds { get; }
    public string ArkansasBounds { get; }

    public static ArkansasFireCoverage Current => CachedCoverage.Value;

    public static ArkansasFireCoverage LoadBundled()
    {
        const string resourceName = "NocIfc.Infrastructure.Regional.arkansas-border-counties-v1.geojson";
        using var stream = typeof(ArkansasFireCoverage).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("Bundled Arkansas county geometry is missing.");
        using var document = JsonDocument.Parse(stream);
        var polygons = new List<Polygon>();
        var regionalCounties = new Dictionary<string, RegionalCountyGeometry>(StringComparer.Ordinal);
        var minLongitude = double.PositiveInfinity;
        var minLatitude = double.PositiveInfinity;
        var maxLongitude = double.NegativeInfinity;
        var maxLatitude = double.NegativeInfinity;
        if (!document.RootElement.TryGetProperty("features", out var features)
            || features.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Bundled Arkansas county geometry is invalid.");
        }

        foreach (var feature in features.EnumerateArray())
        {
            if (!feature.TryGetProperty("properties", out var properties)
                || !feature.TryGetProperty("geometry", out var geometry))
            {
                continue;
            }
            var stateFips = ReadString(properties, "state_fips");
            var geoid = ReadString(properties, "geoid");
            if (stateFips is null && geoid is not null && geoid.Length >= 2)
            {
                stateFips = geoid[..2];
            }
            if (geoid is not null && geoid.Length > 0 && stateFips is not null
                && geometry.ValueKind == JsonValueKind.Object)
            {
                var fips = geoid.PadLeft(5, '0');
                regionalCounties[fips] = new RegionalCountyGeometry(
                    fips,
                    stateFips.PadLeft(2, '0'),
                    JsonNode.Parse(geometry.GetRawText())!);
            }
            if (!string.Equals(stateFips?.PadLeft(2, '0'), "05", StringComparison.Ordinal))
            {
                continue;
            }
            foreach (var polygonRings in ReadPolygons(geometry))
            {
                var rings = new List<Ring>();
                foreach (var rawRing in polygonRings.EnumerateArray())
                {
                    var points = ReadRing(rawRing);
                    if (points.Length < 3)
                    {
                        continue;
                    }
                    rings.Add(new Ring(points));
                    foreach (var point in points)
                    {
                        minLongitude = Math.Min(minLongitude, point.Longitude);
                        minLatitude = Math.Min(minLatitude, point.Latitude);
                        maxLongitude = Math.Max(maxLongitude, point.Longitude);
                        maxLatitude = Math.Max(maxLatitude, point.Latitude);
                    }
                }
                if (rings.Count > 0)
                {
                    polygons.Add(new Polygon(rings.ToArray()));
                }
            }
        }
        if (polygons.Count == 0 || !double.IsFinite(minLongitude))
        {
            throw new InvalidDataException("Bundled Arkansas county geometry contains no Arkansas polygons.");
        }
        return new ArkansasFireCoverage(
            polygons.ToArray(),
            regionalCounties,
            minLongitude,
            minLatitude,
            maxLongitude,
            maxLatitude);
    }

    public bool IncludesPoint(double longitude, double latitude)
    {
        return IncludesArkansasPoint(longitude, latitude) || IncludesBorderPoint(longitude, latitude);
    }

    public bool IncludesArkansasPoint(double longitude, double latitude)
    {
        if (!IsValidCoordinate(longitude, latitude))
        {
            return false;
        }
        if (longitude < _minLongitude || longitude > _maxLongitude
            || latitude < _minLatitude || latitude > _maxLatitude)
        {
            return false;
        }
        var point = new GeographicPoint(longitude, latitude);
        return _arkansasCounties.Any(county => Contains(county, point));
    }

    public bool IncludesBorderPoint(double longitude, double latitude)
    {
        if (!IsValidCoordinate(longitude, latitude)
            || longitude < _bufferMinLongitude || longitude > _bufferMaxLongitude
            || latitude < _bufferMinLatitude || latitude > _bufferMaxLatitude
            || IncludesArkansasPoint(longitude, latitude))
        {
            return false;
        }
        var point = new GeographicPoint(longitude, latitude);
        var projected = Project(point);
        var closest = double.PositiveInfinity;
        foreach (var county in _arkansasCounties)
        {
            foreach (var ring in county.Rings)
            {
                for (var index = 1; index < ring.Projected.Length; index++)
                {
                    closest = Math.Min(closest, DistanceToSegment(projected, ring.Projected[index - 1], ring.Projected[index]));
                }
                closest = Math.Min(closest, DistanceToSegment(projected, ring.Projected[^1], ring.Projected[0]));
                if (closest <= BufferMiles * MilesToMeters)
                {
                    return true;
                }
            }
        }
        return false;
    }

    public bool TryGetAlertGeometryScope(JsonNode? geometry, out string? scope)
    {
        scope = null;
        var lines = new List<GeometryLine>();
        var points = new List<GeographicPoint>();
        if (!CollectGeometry(geometry, lines, points) || points.Count == 0)
        {
            return false;
        }
        var minLongitude = points.Min(point => point.Longitude);
        var maxLongitude = points.Max(point => point.Longitude);
        var minLatitude = points.Min(point => point.Latitude);
        var maxLatitude = points.Max(point => point.Latitude);
        if (maxLongitude < _bufferMinLongitude || minLongitude > _bufferMaxLongitude
            || maxLatitude < _bufferMinLatitude || minLatitude > _bufferMaxLatitude)
        {
            return true;
        }
        if (points.Any(point => IncludesArkansasPoint(point.Longitude, point.Latitude)))
        {
            scope = "arkansas";
            return true;
        }
        var touchesBuffer = points.Any(point => IncludesBorderPoint(point.Longitude, point.Latitude));
        foreach (var county in _arkansasCounties)
        {
            if (county.Rings.Length > 0 && county.Rings[0].Points.Length > 0
                && RegionalGeoJsonViewportFilter.CoversPoint(
                    geometry, county.Rings[0].Points[0].Longitude, county.Rings[0].Points[0].Latitude))
            {
                scope = "arkansas";
                return true;
            }
        }

        foreach (var line in lines)
        {
            var projected = line.Points.Select(Project).ToArray();
            var segmentCount = projected.Length > 1 ? projected.Length - 1 : 0;
            if (line.CloseRing && projected.Length > 2
                && (line.Points[0].Longitude != line.Points[^1].Longitude
                    || line.Points[0].Latitude != line.Points[^1].Latitude))
            {
                segmentCount++;
            }
            for (var alertIndex = 0; alertIndex < segmentCount; alertIndex++)
            {
                var alertStart = projected[alertIndex];
                var alertEnd = projected[(alertIndex + 1) % projected.Length];
                foreach (var county in _arkansasCounties)
                {
                    foreach (var ring in county.Rings)
                    {
                        var boundary = ring.Projected;
                        for (var countyIndex = 1; countyIndex < boundary.Length; countyIndex++)
                        {
                            var stateStart = boundary[countyIndex - 1];
                            var stateEnd = boundary[countyIndex];
                            if (SegmentsIntersect(alertStart, alertEnd, stateStart, stateEnd))
                            {
                                scope = "arkansas";
                                return true;
                            }
                            if (!touchesBuffer && DistanceBetweenSegments(alertStart, alertEnd, stateStart, stateEnd)
                                <= BufferMiles * MilesToMeters)
                            {
                                touchesBuffer = true;
                            }
                        }
                        if (boundary.Length > 2)
                        {
                            var stateStart = boundary[^1];
                            var stateEnd = boundary[0];
                            if (SegmentsIntersect(alertStart, alertEnd, stateStart, stateEnd))
                            {
                                scope = "arkansas";
                                return true;
                            }
                            if (!touchesBuffer && DistanceBetweenSegments(alertStart, alertEnd, stateStart, stateEnd)
                                <= BufferMiles * MilesToMeters)
                            {
                                touchesBuffer = true;
                            }
                        }
                    }
                }
            }
        }
        if (touchesBuffer)
        {
            scope = "border";
        }
        return true;
    }

    public IReadOnlyDictionary<string, RegionalCountyGeometry> GetRegionalCounties() => _regionalCounties;

    private static bool IsValidCoordinate(double longitude, double latitude) =>
        double.IsFinite(longitude) && double.IsFinite(latitude)
        && longitude is >= -180 and <= 180 && latitude is >= -90 and <= 90;

    private static IEnumerable<JsonElement> ReadPolygons(JsonElement geometry)
    {
        if (!geometry.TryGetProperty("type", out var typeElement)
            || typeElement.ValueKind != JsonValueKind.String
            || !geometry.TryGetProperty("coordinates", out var coordinates))
        {
            yield break;
        }
        switch (typeElement.GetString())
        {
            case "Polygon" when coordinates.ValueKind == JsonValueKind.Array:
                yield return coordinates;
                break;
            case "MultiPolygon" when coordinates.ValueKind == JsonValueKind.Array:
                foreach (var polygon in coordinates.EnumerateArray())
                {
                    if (polygon.ValueKind == JsonValueKind.Array)
                    {
                        yield return polygon;
                    }
                }
                break;
        }
    }

    private static GeographicPoint[] ReadRing(JsonElement ring)
    {
        if (ring.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        var points = new List<GeographicPoint>();
        foreach (var position in ring.EnumerateArray())
        {
            if (position.ValueKind != JsonValueKind.Array || position.GetArrayLength() < 2)
            {
                continue;
            }
            var coordinates = position.EnumerateArray();
            if (coordinates.MoveNext() && coordinates.Current.TryGetDouble(out var longitude)
                && coordinates.MoveNext() && coordinates.Current.TryGetDouble(out var latitude)
                && double.IsFinite(longitude) && double.IsFinite(latitude))
            {
                points.Add(new GeographicPoint(longitude, latitude));
            }
        }
        return points.ToArray();
    }

    private static string? ReadString(JsonElement value, string property) =>
        value.TryGetProperty(property, out var propertyValue)
            ? propertyValue.ValueKind switch
            {
                JsonValueKind.String => propertyValue.GetString(),
                JsonValueKind.Number => propertyValue.GetRawText(),
                _ => null,
            }
            : null;

    private static bool Contains(Polygon polygon, GeographicPoint point)
    {
        if (polygon.Rings.Length == 0)
        {
            return false;
        }
        var outer = PointInRing(polygon.Rings[0].Points, point);
        if (outer < 0)
        {
            return false;
        }
        for (var index = 1; index < polygon.Rings.Length; index++)
        {
            var hole = PointInRing(polygon.Rings[index].Points, point);
            if (hole > 0)
            {
                return false;
            }
        }
        return true;
    }

    private static bool CollectGeometry(
        JsonNode? geometry,
        ICollection<GeometryLine> lines,
        ICollection<GeographicPoint> points)
    {
        if (geometry is not JsonObject geometryObject
            || geometryObject["type"] is not JsonValue typeValue
            || !typeValue.TryGetValue<string>(out var type))
        {
            return false;
        }
        var before = points.Count;
        var coordinates = geometryObject["coordinates"];
        switch (type)
        {
            case "Point":
                if (TryReadPosition(coordinates, out var point))
                {
                    points.Add(point);
                }
                break;
            case "MultiPoint":
                if (coordinates is JsonArray pointsArray)
                    foreach (var position in pointsArray)
                        if (TryReadPosition(position, out var multiPoint)) points.Add(multiPoint);
                break;
            case "LineString":
                AddLine(coordinates, false, lines, points);
                break;
            case "MultiLineString":
                if (coordinates is JsonArray multiLines)
                    foreach (var line in multiLines) AddLine(line, false, lines, points);
                break;
            case "Polygon":
                if (coordinates is JsonArray rings)
                    foreach (var ring in rings) AddLine(ring, true, lines, points);
                break;
            case "MultiPolygon":
                if (coordinates is JsonArray polygons)
                    foreach (var polygon in polygons.OfType<JsonArray>())
                        foreach (var ring in polygon) AddLine(ring, true, lines, points);
                break;
            case "GeometryCollection":
                if (geometryObject["geometries"] is JsonArray geometries)
                    foreach (var item in geometries) CollectGeometry(item, lines, points);
                break;
            default:
                return false;
        }
        return points.Count > before;
    }

    private static void AddLine(
        JsonNode? coordinates,
        bool closeRing,
        ICollection<GeometryLine> lines,
        ICollection<GeographicPoint> points)
    {
        if (coordinates is not JsonArray positions) return;
        var line = ReadGeometryLine(positions);
        if (line.Length == 0) return;
        lines.Add(new GeometryLine(line, closeRing));
        foreach (var point in line) points.Add(point);
    }

    private static GeographicPoint[] ReadGeometryLine(JsonArray positions)
    {
        var line = new List<GeographicPoint>();
        foreach (var position in positions)
        {
            if (TryReadPosition(position, out var point)) line.Add(point);
        }
        return line.ToArray();
    }

    private static bool TryReadPosition(JsonNode? position, out GeographicPoint point)
    {
        point = default;
        if (position is not JsonArray coordinates || coordinates.Count < 2
            || !TryReadNumber(coordinates[0], out var longitude)
            || !TryReadNumber(coordinates[1], out var latitude))
        {
            return false;
        }
        point = new GeographicPoint(longitude, latitude);
        return true;
    }

    private static bool TryReadNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out number))
        {
            return double.IsFinite(number);
        }
        number = 0;
        return false;
    }

    private static bool SegmentsIntersect(
        ProjectedPoint firstStart,
        ProjectedPoint firstEnd,
        ProjectedPoint secondStart,
        ProjectedPoint secondEnd)
    {
        const double epsilon = 1e-4;
        var firstOrientation = Orientation(firstStart, firstEnd, secondStart);
        var secondOrientation = Orientation(firstStart, firstEnd, secondEnd);
        var thirdOrientation = Orientation(secondStart, secondEnd, firstStart);
        var fourthOrientation = Orientation(secondStart, secondEnd, firstEnd);
        if (((firstOrientation > epsilon && secondOrientation < -epsilon)
             || (firstOrientation < -epsilon && secondOrientation > epsilon))
            && ((thirdOrientation > epsilon && fourthOrientation < -epsilon)
                || (thirdOrientation < -epsilon && fourthOrientation > epsilon)))
        {
            return true;
        }
        return Math.Abs(firstOrientation) <= epsilon && OnSegment(firstStart, firstEnd, secondStart)
            || Math.Abs(secondOrientation) <= epsilon && OnSegment(firstStart, firstEnd, secondEnd)
            || Math.Abs(thirdOrientation) <= epsilon && OnSegment(secondStart, secondEnd, firstStart)
            || Math.Abs(fourthOrientation) <= epsilon && OnSegment(secondStart, secondEnd, firstEnd);
    }

    private static double Orientation(ProjectedPoint start, ProjectedPoint end, ProjectedPoint point) =>
        (end.X - start.X) * (point.Y - start.Y) - (end.Y - start.Y) * (point.X - start.X);

    private static bool OnSegment(ProjectedPoint start, ProjectedPoint end, ProjectedPoint point)
    {
        const double epsilon = 1e-4;
        return point.X >= Math.Min(start.X, end.X) - epsilon && point.X <= Math.Max(start.X, end.X) + epsilon
            && point.Y >= Math.Min(start.Y, end.Y) - epsilon && point.Y <= Math.Max(start.Y, end.Y) + epsilon;
    }

    private static double DistanceBetweenSegments(
        ProjectedPoint firstStart,
        ProjectedPoint firstEnd,
        ProjectedPoint secondStart,
        ProjectedPoint secondEnd)
    {
        if (SegmentsIntersect(firstStart, firstEnd, secondStart, secondEnd)) return 0;
        return Math.Min(
            Math.Min(DistanceToSegment(firstStart, secondStart, secondEnd), DistanceToSegment(firstEnd, secondStart, secondEnd)),
            Math.Min(DistanceToSegment(secondStart, firstStart, firstEnd), DistanceToSegment(secondEnd, firstStart, firstEnd)));
    }

    private static int PointInRing(GeographicPoint[] ring, GeographicPoint point)
    {
        var inside = false;
        for (var index = 0; index < ring.Length; index++)
        {
            var current = ring[index];
            var previous = ring[(index + ring.Length - 1) % ring.Length];
            var cross = (point.Latitude - previous.Latitude) * (current.Longitude - previous.Longitude)
                - (point.Longitude - previous.Longitude) * (current.Latitude - previous.Latitude);
            if (Math.Abs(cross) <= 1e-10
                && point.Longitude >= Math.Min(previous.Longitude, current.Longitude) - 1e-10
                && point.Longitude <= Math.Max(previous.Longitude, current.Longitude) + 1e-10
                && point.Latitude >= Math.Min(previous.Latitude, current.Latitude) - 1e-10
                && point.Latitude <= Math.Max(previous.Latitude, current.Latitude) + 1e-10)
            {
                return 0;
            }
            if ((current.Latitude > point.Latitude) != (previous.Latitude > point.Latitude)
                && point.Longitude < (previous.Longitude - current.Longitude)
                    * (point.Latitude - current.Latitude) / (previous.Latitude - current.Latitude) + current.Longitude)
            {
                inside = !inside;
            }
        }
        return inside ? 1 : -1;
    }

    private ProjectedPoint Project(GeographicPoint point)
    {
        const double flattening = Flattening;
        const double semiMinorMeters = SemiMajorMeters * (1 - flattening);
        var latitude1 = _centerLatitude * DegreesToRadians;
        var latitude2 = point.Latitude * DegreesToRadians;
        var longitudeDifference = NormalizeRadians((point.Longitude - _centerLongitude) * DegreesToRadians);
        var reducedLatitude1 = Math.Atan((1 - flattening) * Math.Tan(latitude1));
        var reducedLatitude2 = Math.Atan((1 - flattening) * Math.Tan(latitude2));
        var sinReduced1 = Math.Sin(reducedLatitude1);
        var cosReduced1 = Math.Cos(reducedLatitude1);
        var sinReduced2 = Math.Sin(reducedLatitude2);
        var cosReduced2 = Math.Cos(reducedLatitude2);
        var lambda = longitudeDifference;
        double sinSigma = 0;
        double cosSigma = 0;
        double sigma = 0;
        double sinAlpha = 0;
        double cosSquaredAlpha = 0;
        double cosDoubleSigmaMiddle = 0;
        for (var iteration = 0; iteration < 100; iteration++)
        {
            var sinLambda = Math.Sin(lambda);
            var cosLambda = Math.Cos(lambda);
            sinSigma = Math.Sqrt(
                Math.Pow(cosReduced2 * sinLambda, 2)
                + Math.Pow(cosReduced1 * sinReduced2 - sinReduced1 * cosReduced2 * cosLambda, 2));
            if (sinSigma == 0)
            {
                return new ProjectedPoint(0, 0);
            }
            cosSigma = sinReduced1 * sinReduced2 + cosReduced1 * cosReduced2 * cosLambda;
            sigma = Math.Atan2(sinSigma, cosSigma);
            sinAlpha = cosReduced1 * cosReduced2 * sinLambda / sinSigma;
            cosSquaredAlpha = 1 - sinAlpha * sinAlpha;
            cosDoubleSigmaMiddle = cosSquaredAlpha == 0
                ? 0
                : cosSigma - 2 * sinReduced1 * sinReduced2 / cosSquaredAlpha;
            var coefficient = flattening / 16 * cosSquaredAlpha
                * (4 + flattening * (4 - 3 * cosSquaredAlpha));
            var previousLambda = lambda;
            lambda = longitudeDifference + (1 - coefficient) * flattening * sinAlpha
                * (sigma + coefficient * sinSigma
                    * (cosDoubleSigmaMiddle + coefficient * cosSigma
                        * (-1 + 2 * cosDoubleSigmaMiddle * cosDoubleSigmaMiddle)));
            if (Math.Abs(lambda - previousLambda) < 1e-12)
            {
                break;
            }
        }
        var squaredU = cosSquaredAlpha
            * (SemiMajorMeters * SemiMajorMeters - semiMinorMeters * semiMinorMeters)
            / (semiMinorMeters * semiMinorMeters);
        var coefficientA = 1 + squaredU / 16384
            * (4096 + squaredU * (-768 + squaredU * (320 - 175 * squaredU)));
        var coefficientB = squaredU / 1024
            * (256 + squaredU * (-128 + squaredU * (74 - 47 * squaredU)));
        var deltaSigma = coefficientB * sinSigma
            * (cosDoubleSigmaMiddle + coefficientB / 4
                * (cosSigma * (-1 + 2 * cosDoubleSigmaMiddle * cosDoubleSigmaMiddle)
                    - coefficientB / 6 * cosDoubleSigmaMiddle
                        * (-3 + 4 * sinSigma * sinSigma)
                        * (-3 + 4 * cosDoubleSigmaMiddle * cosDoubleSigmaMiddle)));
        var distance = semiMinorMeters * coefficientA * (sigma - deltaSigma);
        var initialBearing = Math.Atan2(
            cosReduced2 * Math.Sin(lambda),
            cosReduced1 * sinReduced2 - sinReduced1 * cosReduced2 * Math.Cos(lambda));
        return new ProjectedPoint(distance * Math.Sin(initialBearing), distance * Math.Cos(initialBearing));
    }

    private static double NormalizeRadians(double radians)
    {
        while (radians > Math.PI) radians -= 2 * Math.PI;
        while (radians < -Math.PI) radians += 2 * Math.PI;
        return radians;
    }

    private static double DistanceToSegment(ProjectedPoint point, ProjectedPoint start, ProjectedPoint end)
    {
        var deltaX = end.X - start.X;
        var deltaY = end.Y - start.Y;
        var lengthSquared = deltaX * deltaX + deltaY * deltaY;
        if (lengthSquared == 0)
        {
            return Distance(point, start);
        }
        var fraction = Math.Clamp(
            ((point.X - start.X) * deltaX + (point.Y - start.Y) * deltaY) / lengthSquared,
            0,
            1);
        return Distance(point, new ProjectedPoint(start.X + fraction * deltaX, start.Y + fraction * deltaY));
    }

    private static double Distance(ProjectedPoint first, ProjectedPoint second) =>
        Math.Sqrt(Math.Pow(first.X - second.X, 2) + Math.Pow(first.Y - second.Y, 2));

    private sealed record Polygon(Ring[] Rings);
    private sealed record GeometryLine(GeographicPoint[] Points, bool CloseRing);
    private sealed class Ring(GeographicPoint[] points)
    {
        public GeographicPoint[] Points { get; } = points;
        public ProjectedPoint[] Projected { get; set; } = [];
    }
    private readonly record struct GeographicPoint(double Longitude, double Latitude);
    private readonly record struct ProjectedPoint(double X, double Y);
}
