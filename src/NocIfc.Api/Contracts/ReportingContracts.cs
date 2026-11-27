using System.Text.Json.Serialization;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed class DailyFusionBroadcastRequest
{
    [JsonPropertyName("report_date")]
    public string? ReportDate { get; init; } = "";

    [JsonPropertyName("content")]
    public string? Content { get; init; } = "";

    [JsonPropertyName("recipients")]
    public string? Recipients { get; init; } = "";
}

public sealed class CustomReportBroadcastRequest
{
    [JsonPropertyName("title")]
    public string? Title { get; init; } = "NOC Custom Intel Report";

    [JsonPropertyName("content")]
    public string? Content { get; init; } = "";

    [JsonPropertyName("recipients")]
    public string? Recipients { get; init; } = "";
}

public sealed class ReportingArticleSearchRequest
{
    [JsonPropertyName("target")]
    public string Target { get; init; } = "";

    [JsonPropertyName("days_back")]
    public int DaysBack { get; init; } = 7;
}

public sealed class CustomReportGenerationRequest
{
    [JsonPropertyName("target")]
    public string? Target { get; init; } = "";

    [JsonPropertyName("days_back")]
    public int DaysBack { get; init; } = 7;

    [JsonPropertyName("article_ids")]
    public IReadOnlyList<int>? ArticleIds { get; init; } = [];

    [JsonPropertyName("objective")]
    public string? Objective { get; init; } = "";

    [JsonPropertyName("analyst")]
    public string? Analyst { get; init; } = "Unknown";
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
