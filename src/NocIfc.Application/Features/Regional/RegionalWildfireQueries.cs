using System.Globalization;
using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed class RegionalWildfireQueries(IRegionalWildfireProvider wildfires)
{
    public async Task<JsonNode?> GetAsync(string? bbox, CancellationToken cancellationToken)
    {
        var viewport = RegionalDataQueries.ParseBoundingBox(bbox);
        var payload = JsonNode.Parse(await wildfires.GetActiveWildfiresJsonAsync(cancellationToken));
        if (viewport is null || payload is not JsonObject data)
        {
            return payload;
        }

        if (data["incidents"] is JsonArray incidents)
        {
            var visible = new JsonArray();
            foreach (var incident in incidents)
            {
                if (incident is not JsonObject fire
                    || !TryNumber(fire["lon"], out var longitude)
                    || !TryNumber(fire["lat"], out var latitude))
                {
                    continue;
                }
                if (longitude >= viewport.Value.West && longitude <= viewport.Value.East
                    && latitude >= viewport.Value.South && latitude <= viewport.Value.North)
                {
                    visible.Add(incident.DeepClone());
                }
            }
            data["incidents"] = visible;
        }

        FilterGeometryList(data, "perimeters", viewport.Value);
        FilterGeometryList(data, "footprints", viewport.Value);
        return data;
    }

    private static void FilterGeometryList(JsonObject data, string key, Wgs84Box viewport)
    {
        if (data[key] is not JsonArray features)
        {
            return;
        }
        var visible = new JsonArray();
        foreach (var feature in features)
        {
            if (feature is not JsonObject item
                || RegionalGeoJsonViewportFilter.IntersectsViewport(item["geometry"], viewport))
            {
                visible.Add(feature?.DeepClone());
            }
        }
        data[key] = visible;
    }

    private static bool TryNumber(JsonNode? value, out double number)
    {
        if (value is JsonValue jsonValue && jsonValue.TryGetValue<double>(out number) && double.IsFinite(number))
        {
            return true;
        }
        if (value is JsonValue stringValue && stringValue.TryGetValue<string>(out var text)
            && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
            && double.IsFinite(number))
        {
            return true;
        }
        number = 0;
        return false;
    }
}
