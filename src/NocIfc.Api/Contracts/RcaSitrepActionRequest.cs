using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.AIOps;

namespace NocIfc.Api.Contracts;

public sealed class RcaSitrepActionRequest
{
    [JsonPropertyName("action")]
    public string? Action { get; init; }

    [JsonPropertyName("intel")]
    public JsonObject? Intel { get; init; }

    public AiopsScoringRationaleInput ToIntelInput()
    {
        var cyber = Articles("raw_cyber_articles");
        var physical = Articles("raw_phys_articles");
        var crimes = Intel?["recent_crimes"] is JsonArray crimeArray
            ? crimeArray.OfType<JsonObject>().Select(crime => new AiopsScoringRationaleCrime(
                GetText(crime, "fbi_category"), GetText(crime, "raw_title"), GetText(crime, "distance_miles")))
                .ToArray()
            : [];
        return new AiopsScoringRationaleInput(GetText(Intel, "unified_risk"), cyber, physical, crimes);
    }

    private AiopsScoringRationaleArticle[] Articles(string property) =>
        Intel?[property] is JsonArray articleArray
            ? articleArray.OfType<JsonObject>().Select(article => new AiopsScoringRationaleArticle(
                GetText(article, "source"), GetText(article, "category"), GetText(article, "title"),
                GetText(article, "summary"))).ToArray()
            : [];

    private static string? GetText(JsonObject? source, string property)
    {
        if (source is null || !source.TryGetPropertyValue(property, out var node) || node is null) return null;
        if (node is JsonValue value && value.TryGetValue<string>(out var text)) return text;
        if (node is JsonValue boolean && boolean.TryGetValue<bool>(out var flag)) return flag ? "True" : "False";
        return node.ToJsonString();
    }
}
