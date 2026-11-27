using System.Text.Json.Serialization;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed class ReportingArticleSearchRequest
{
    [JsonPropertyName("target")]
    public string Target { get; init; } = "";

    [JsonPropertyName("days_back")]
    public int DaysBack { get; init; } = 7;
}

public sealed record ReportingArticleSearchItem(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("score")] double Score,
    [property: JsonPropertyName("published_date")] DateTime? PublishedDate,
    [property: JsonPropertyName("summary")] string Summary,
    [property: JsonPropertyName("category")] string Category)
{
    public static ReportingArticleSearchItem From(ThreatArticle article) => new(
        article.Id,
        article.Title ?? "",
        article.Source ?? "",
        article.Score ?? 0,
        article.PublishedDate,
        (article.Summary ?? "")[..Math.Min((article.Summary ?? "").Length, 300)],
        article.Category ?? "");
}
