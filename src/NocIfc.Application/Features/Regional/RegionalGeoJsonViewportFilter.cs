using System.Globalization;
using System.Text.Json.Nodes;

namespace NocIfc.Application.Features.Regional;

public readonly record struct Wgs84Box(double West, double South, double East, double North);

public static class RegionalGeoJsonViewportFilter
{
    public static JsonNode FilterCurrentAlerts(JsonNode? collection, DateTime nowUtc)
    {
        var result = new JsonObject { ["type"] = "FeatureCollection" };
        var features = new JsonArray();
        if (collection is JsonObject source && source["features"] is JsonArray sourceFeatures)
        {
            foreach (var feature in sourceFeatures)
            {
                if (IsCurrentAlert(feature, nowUtc))
                {
                    features.Add(feature?.DeepClone());
                }
            }
        }
        result["features"] = features;
        return result;
    }

    public static JsonNode? FilterToViewport(JsonNode? collection, Wgs84Box viewport)
    {
        if (collection is not JsonObject source || source["features"] is not JsonArray sourceFeatures)
        {
            return collection;
        }
        var result = (JsonObject)source.DeepClone();
        var visible = new JsonArray();
        foreach (var feature in sourceFeatures)
        {
            if (feature is not JsonObject featureObject
                || featureObject["geometry"] is not JsonObject geometry
                || GeometryIntersects(geometry, viewport) is not false)
            {
                visible.Add(feature?.DeepClone());
            }
        }
        result["features"] = visible;
        return result;
    }

    private static bool IsCurrentAlert(JsonNode? feature, DateTime nowUtc)
    {
        var properties = feature is JsonObject featureObject ? featureObject["properties"] as JsonObject : null;
        if (string.Equals(ReadString(properties?["messageType"]), "cancel", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        var expires = ReadUtcDate(properties?["expires"]);
        if (expires is { } expiry && expiry <= nowUtc)
        {
            return false;
        }
        var effective = ReadUtcDate(properties?["effective"]);
        return effective is null || effective <= nowUtc;
    }

    private static bool? GeometryIntersects(JsonObject geometry, Wgs84Box viewport)
    {
        var type = ReadString(geometry["type"]);
        var coordinates = geometry["coordinates"];
        return type switch
        {
            "Point" => PointIntersects(coordinates, viewport),
            "MultiPoint" => MultiPointIntersects(coordinates, viewport),
            "LineString" => LineIntersects(coordinates, viewport, closeRing: false),
            "MultiLineString" => MultiLineIntersects(coordinates, viewport),
            "Polygon" => PolygonIntersects(coordinates, viewport),
            "MultiPolygon" => MultiPolygonIntersects(coordinates, viewport),
            "GeometryCollection" => GeometryCollectionIntersects(geometry["geometries"], viewport),
            _ => null,
        };
    }

    private static bool? PointIntersects(JsonNode? coordinate, Wgs84Box viewport)
    {
        if (!TryPoint(coordinate, out var point))
        {
            return null;
        }
        return Contains(viewport, point);
    }

    private static bool? MultiPointIntersects(JsonNode? coordinates, Wgs84Box viewport)
    {
        if (coordinates is not JsonArray points)
        {
            return null;
        }
        var malformed = false;
        foreach (var coordinate in points)
        {
            var intersects = PointIntersects(coordinate, viewport);
            if (intersects == true)
            {
                return true;
            }
            malformed |= intersects is null;
        }
        return malformed ? null : false;
    }

    private static bool? MultiLineIntersects(JsonNode? coordinates, Wgs84Box viewport)
    {
        if (coordinates is not JsonArray lines)
        {
            return null;
        }
        var malformed = false;
        foreach (var line in lines)
        {
            var intersects = LineIntersects(line, viewport, closeRing: false);
            if (intersects == true)
            {
                return true;
            }
            malformed |= intersects is null;
        }
        return malformed ? null : false;
    }

    private static bool? PolygonIntersects(JsonNode? coordinates, Wgs84Box viewport)
    {
        if (coordinates is not JsonArray rings)
        {
            return null;
        }
        if (rings.Count == 0)
        {
            return false;
        }
        var malformed = false;
        foreach (var ring in rings)
        {
            var ringIntersects = LineIntersects(ring, viewport, closeRing: true);
            if (ringIntersects == true)
            {
                return true;
            }
            malformed |= ringIntersects is null;
        }

        foreach (var corner in Corners(viewport))
        {
            var outer = PointInRing(rings[0], corner);
            if (outer is null)
            {
                malformed = true;
                continue;
            }
            if (outer == 0)
            {
                return true;
            }
            if (outer < 0)
            {
                continue;
            }

            var insideHole = false;
            for (var index = 1; index < rings.Count; index++)
            {
                var hole = PointInRing(rings[index], corner);
                if (hole is null)
                {
                    malformed = true;
                    continue;
                }
                if (hole == 0)
                {
                    return true;
                }
                if (hole > 0)
                {
                    insideHole = true;
                    break;
                }
            }
            if (!insideHole)
            {
                return true;
            }
        }
        return malformed ? null : false;
    }

    private static bool? MultiPolygonIntersects(JsonNode? coordinates, Wgs84Box viewport)
    {
        if (coordinates is not JsonArray polygons)
        {
            return null;
        }
        var malformed = false;
        foreach (var polygon in polygons)
        {
            var intersects = PolygonIntersects(polygon, viewport);
            if (intersects == true)
            {
                return true;
            }
            malformed |= intersects is null;
        }
        return malformed ? null : false;
    }

    private static bool? GeometryCollectionIntersects(JsonNode? geometries, Wgs84Box viewport)
    {
        if (geometries is not JsonArray items)
        {
            return null;
        }
        var malformed = false;
        foreach (var item in items)
        {
            if (item is not JsonObject geometry)
            {
                malformed = true;
                continue;
            }
            var intersects = GeometryIntersects(geometry, viewport);
            if (intersects == true)
            {
                return true;
            }
            malformed |= intersects is null;
        }
        return malformed ? null : false;
    }

    private static bool? LineIntersects(JsonNode? coordinates, Wgs84Box viewport, bool closeRing)
    {
        if (coordinates is not JsonArray values)
        {
            return null;
        }
        var points = new List<Point>(values.Count);
        foreach (var value in values)
        {
            if (!TryPoint(value, out var point))
            {
                return null;
            }
            points.Add(point);
        }
        if (points.Count == 0)
        {
            return false;
        }
        if (points.Count == 1)
        {
            return Contains(viewport, points[0]);
        }
        for (var index = 1; index < points.Count; index++)
        {
            if (SegmentIntersects(viewport, points[index - 1], points[index]))
            {
                return true;
            }
        }
        return closeRing && points.Count > 2
            ? SegmentIntersects(viewport, points[^1], points[0])
            : false;
    }

    private static int? PointInRing(JsonNode? ring, Point point)
    {
        if (ring is not JsonArray coordinates || coordinates.Count < 3)
        {
            return null;
        }
        var points = new List<Point>(coordinates.Count);
        foreach (var coordinate in coordinates)
        {
            if (!TryPoint(coordinate, out var ringPoint))
            {
                return null;
            }
            points.Add(ringPoint);
        }
        var inside = false;
        for (var index = 0; index < points.Count; index++)
        {
            var current = points[index];
            var previous = points[(index + points.Count - 1) % points.Count];
            if (OnSegment(previous, current, point))
            {
                return 0;
            }
            if ((current.Y > point.Y) != (previous.Y > point.Y)
                && point.X < (previous.X - current.X) * (point.Y - current.Y)
                    / (previous.Y - current.Y) + current.X)
            {
                inside = !inside;
            }
        }
        return inside ? 1 : -1;
    }

    private static bool SegmentIntersects(Wgs84Box box, Point start, Point end)
    {
        if (Contains(box, start) || Contains(box, end))
        {
            return true;
        }
        var deltaX = end.X - start.X;
        var deltaY = end.Y - start.Y;
        var lower = 0d;
        var upper = 1d;
        ReadOnlySpan<double> p = [-deltaX, deltaX, -deltaY, deltaY];
        ReadOnlySpan<double> q =
        [
            start.X - box.West,
            box.East - start.X,
            start.Y - box.South,
            box.North - start.Y,
        ];
        for (var index = 0; index < 4; index++)
        {
            if (p[index] == 0)
            {
                if (q[index] < 0)
                {
                    return false;
                }
                continue;
            }
            var ratio = q[index] / p[index];
            if (p[index] < 0)
            {
                lower = Math.Max(lower, ratio);
            }
            else
            {
                upper = Math.Min(upper, ratio);
            }
            if (lower > upper)
            {
                return false;
            }
        }
        return true;
    }

    private static bool OnSegment(Point start, Point end, Point point)
    {
        const double tolerance = 1e-10;
        var cross = (point.Y - start.Y) * (end.X - start.X) - (point.X - start.X) * (end.Y - start.Y);
        return Math.Abs(cross) <= tolerance
            && point.X >= Math.Min(start.X, end.X) - tolerance
            && point.X <= Math.Max(start.X, end.X) + tolerance
            && point.Y >= Math.Min(start.Y, end.Y) - tolerance
            && point.Y <= Math.Max(start.Y, end.Y) + tolerance;
    }

    private static bool Contains(Wgs84Box box, Point point) =>
        point.X >= box.West && point.X <= box.East && point.Y >= box.South && point.Y <= box.North;

    private static IEnumerable<Point> Corners(Wgs84Box box)
    {
        yield return new Point(box.West, box.South);
        yield return new Point(box.West, box.North);
        yield return new Point(box.East, box.South);
        yield return new Point(box.East, box.North);
    }

    private static bool TryPoint(JsonNode? coordinate, out Point point)
    {
        point = default;
        if (coordinate is not JsonArray values || values.Count < 2
            || !TryNumber(values[0], out var longitude)
            || !TryNumber(values[1], out var latitude))
        {
            return false;
        }
        point = new Point(longitude, latitude);
        return true;
    }

    private static bool TryNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out number))
        {
            return double.IsFinite(number);
        }
        number = 0;
        return false;
    }

    private static string? ReadString(JsonNode? value)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<string>(out var text))
        {
            return text;
        }
        return null;
    }

    private static DateTimeOffset? ReadUtcDate(JsonNode? value)
    {
        var text = ReadString(value);
        return DateTimeOffset.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed)
                ? parsed
                : null;
    }

    private readonly record struct Point(double X, double Y);
}
