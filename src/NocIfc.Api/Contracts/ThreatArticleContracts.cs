using System.Text.Json.Serialization;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed record ThreatArticleKeywordResponse(
    [property: JsonPropertyName("word")] string Word,
    [property: JsonPropertyName("weight")] int Weight)
{
    public static ThreatArticleKeywordResponse From(ThreatArticleKeyword keyword) =>
        new(keyword.Word, keyword.Weight);
}

public sealed record ThreatArticleIocResponse(
    [property: JsonPropertyName("indicator_type")] string? IndicatorType,
    [property: JsonPropertyName("indicator_value")] string? IndicatorValue,
    [property: JsonPropertyName("context")] string? Context)
{
    public static ThreatArticleIocResponse From(ThreatArticleIoc ioc) =>
        new(ioc.IndicatorType, ioc.IndicatorValue, ioc.Context);
}

public sealed record ThreatArticleResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("link")] string? Link,
    [property: JsonPropertyName("summary")] string? Summary,
    [property: JsonPropertyName("published_date")] DateTime? PublishedDate,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("category")] string? Category,
    [property: JsonPropertyName("keywords_found")] IReadOnlyList<string>? KeywordsFound,
    [property: JsonPropertyName("is_bubbled")] bool? IsBubbled,
    [property: JsonPropertyName("story_group")] string? StoryGroup,
    [property: JsonPropertyName("full_content")] string? FullContent,
    [property: JsonPropertyName("ai_bluf")] string? AiBluf,
    [property: JsonPropertyName("is_pinned")] bool? IsPinned,
    [property: JsonPropertyName("ingested_at")] DateTime? IngestedAt,
    [property: JsonPropertyName("enrichment_status")] string? EnrichmentStatus,
    [property: JsonPropertyName("enrichment_attempts")] int? EnrichmentAttempts,
    [property: JsonPropertyName("last_enrichment_error")] string? LastEnrichmentError,
    [property: JsonPropertyName("last_enriched_at")] DateTime? LastEnrichedAt,
    [property: JsonPropertyName("keywords_with_weights"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<ThreatArticleKeywordResponse>? KeywordsWithWeights,
    [property: JsonPropertyName("total_keyword_score"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? TotalKeywordScore,
    [property: JsonPropertyName("iocs"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<ThreatArticleIocResponse>? Iocs,
    [property: JsonPropertyName("is_utility_related"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IsUtilityRelated,
    [property: JsonPropertyName("is_apt_related"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IsAptRelated,
    [property: JsonPropertyName("is_ransomware"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IsRansomware)
{
    public static ThreatArticleResponse From(ThreatArticle article) => new(
        article.Id,
        article.Title,
        article.Link,
        article.Summary,
        article.PublishedDate,
        article.Source,
        article.Score,
        article.Category,
        article.KeywordsFound,
        article.IsBubbled,
        article.StoryGroup,
        article.FullContent,
        article.AiBluf,
        article.IsPinned,
        article.IngestedAt,
        article.EnrichmentStatus,
        article.EnrichmentAttempts,
        article.LastEnrichmentError,
        article.LastEnrichedAt,
        null,
        null,
        null,
        null,
        null,
        null);

    public static ThreatArticleResponse From(ThreatArticleDetail detail) =>
        From(detail.Article) with
        {
            KeywordsWithWeights = detail.KeywordsWithWeights.Select(ThreatArticleKeywordResponse.From).ToArray(),
            TotalKeywordScore = detail.TotalKeywordScore,
            Iocs = detail.Iocs.Select(ThreatArticleIocResponse.From).ToArray(),
        };

    public static ThreatArticleResponse FromExecutive(ExecutiveIntelArticle article) =>
        From(article.Article) with
        {
            IsUtilityRelated = article.IsUtilityRelated,
            IsAptRelated = article.IsAptRelated,
            IsRansomware = article.IsRansomware,
        };
}

public sealed record ThreatArticlePageResponse(
    [property: JsonPropertyName("items")] IReadOnlyList<ThreatArticleResponse> Items,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("total_pages")] int TotalPages,
    [property: JsonPropertyName("page")] int Page)
{
    public static ThreatArticlePageResponse From(ThreatArticlePage result) => new(
        result.Items.Select(ThreatArticleResponse.From).ToArray(),
        result.Total,
        result.TotalPages,
        result.Page);
}
