using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;

namespace NocIfc.Application.Features.Regional;

public sealed class RegionalForecastQueries(INwsForecastProvider forecasts)
{
    public async Task<JsonNode?> GetAsync(double latitude, double longitude, CancellationToken cancellationToken)
    {
        if (!double.IsFinite(latitude) || latitude is < -90 or > 90)
        {
            throw new ArgumentOutOfRangeException(nameof(latitude), "lat must be between -90 and 90.");
        }
        if (!double.IsFinite(longitude) || longitude is < -180 or > 180)
        {
            throw new ArgumentOutOfRangeException(nameof(longitude), "lon must be between -180 and 180.");
        }
        var periods = await forecasts.GetForecastPeriodsJsonAsync(latitude, longitude, cancellationToken);
        return periods is null ? null : JsonNode.Parse(periods);
    }
}
