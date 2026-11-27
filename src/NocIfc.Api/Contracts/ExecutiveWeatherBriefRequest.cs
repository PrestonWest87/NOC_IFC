using System.Text.Json;
using System.Text.Json.Serialization;

namespace NocIfc.Api.Contracts;

public sealed class ExecutiveWeatherBriefRequest
{
    [JsonPropertyName("analytics")]
    public JsonElement? Analytics { get; init; }

    [JsonPropertyName("p1_at_risk")]
    public int P1AtRisk { get; init; }
}
