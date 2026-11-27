using System.Text.Json.Serialization;
using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Api.Contracts;

public sealed record KeywordAnalysisOverviewResponse(
    [property: JsonPropertyName("total_keywords")] int TotalKeywords,
    [property: JsonPropertyName("total_articles")] int TotalArticles,
    [property: JsonPropertyName("avg_weight")] double AverageWeight,
    [property: JsonPropertyName("max_weight")] int MaximumWeight,
    [property: JsonPropertyName("min_weight")] int MinimumWeight,
    [property: JsonPropertyName("keywords_used")] int KeywordsUsed,
    [property: JsonPropertyName("keywords_unused")] int KeywordsUnused,
    [property: JsonPropertyName("articles_with_keywords")] int ArticlesWithKeywords,
    [property: JsonPropertyName("articles_without_keywords")] int ArticlesWithoutKeywords)
{
    public static KeywordAnalysisOverviewResponse From(KeywordAnalysisOverview result) => new(
        result.TotalKeywords, result.TotalArticles, result.AverageWeight, result.MaximumWeight, result.MinimumWeight,
        result.KeywordsUsed, result.KeywordsUnused, result.ArticlesWithKeywords, result.ArticlesWithoutKeywords);
}

public sealed record KeywordAnalysisStatResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("word")] string Word,
    [property: JsonPropertyName("weight")] int Weight,
    [property: JsonPropertyName("trigger_count")] int TriggerCount,
    [property: JsonPropertyName("avg_score_contribution")] double AverageScoreContribution)
{
    public static KeywordAnalysisStatResponse From(KeywordAnalysisStat result) => new(
        result.Id, result.Word, result.Weight, result.TriggerCount, result.AverageScoreContribution);
}

public sealed record KeywordCategoryDistributionResponse(
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("avg_score")] double AverageScore,
    [property: JsonPropertyName("percent")] double Percent)
{
    public static KeywordCategoryDistributionResponse From(KeywordCategoryDistribution result) => new(
        result.Category, result.Count, result.AverageScore, result.Percent);
}

public sealed record KeywordAnalysisTimelineResponse(
    [property: JsonPropertyName("date")] string Date,
    [property: JsonPropertyName("total_articles")] int TotalArticles,
    [property: JsonPropertyName("matched_articles")] int MatchedArticles,
    [property: JsonPropertyName("match_rate")] double MatchRate,
    [property: JsonPropertyName("avg_score")] double AverageScore)
{
    public static KeywordAnalysisTimelineResponse From(KeywordAnalysisTimelinePoint result) => new(
        result.Date, result.TotalArticles, result.MatchedArticles, result.MatchRate, result.AverageScore);
}

public sealed record KeywordAnalysisArticleResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("category")] string? Category,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("published_date")] DateTime? PublishedDate,
    [property: JsonPropertyName("keywords_found")] IReadOnlyList<string> KeywordsFound)
{
    public static KeywordAnalysisArticleResponse From(KeywordAnalysisArticle result) => new(
        result.Id, result.Title, result.Source, result.Category, result.Score, result.PublishedDate, result.KeywordsFound);
}

public sealed record KeywordScoreBucketResponse(
    [property: JsonPropertyName("bucket")] string Bucket,
    [property: JsonPropertyName("count")] int Count,
    [property: JsonPropertyName("top_category")] string TopCategory)
{
    public static KeywordScoreBucketResponse From(KeywordScoreBucket result) =>
        new(result.Bucket, result.Count, result.TopCategory);
}

public sealed record KeywordCategoryMatrixResponse(
    [property: JsonPropertyName("categories")] IReadOnlyList<string> Categories,
    [property: JsonPropertyName("keywords")] IReadOnlyList<string> Keywords,
    [property: JsonPropertyName("matrix")] IReadOnlyList<IReadOnlyDictionary<string, object?>> Matrix)
{
    public static KeywordCategoryMatrixResponse From(KeywordCategoryMatrix result) =>
        new(result.Categories, result.Keywords, result.Matrix);
}

public sealed record KeywordOccurrenceResponse(
    [property: JsonPropertyName("word")] string Word,
    [property: JsonPropertyName("count")] int Count)
{
    public static KeywordOccurrenceResponse From(KeywordOccurrence result) => new(result.Word, result.Count);
}

public sealed record KeywordSourceCountResponse(
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("count")] int Count)
{
    public static KeywordSourceCountResponse From(KeywordSourceCount result) => new(result.Source, result.Count);
}

public sealed record KeywordRecentArticleResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("published_date")] DateTime? PublishedDate,
    [property: JsonPropertyName("keywords_found")] IReadOnlyList<string> KeywordsFound)
{
    public static KeywordRecentArticleResponse From(KeywordRecentArticle result) => new(
        result.Id, result.Title, result.Source, result.Score, result.PublishedDate, result.KeywordsFound);
}

public sealed record KeywordCategoryDetailsResponse(
    [property: JsonPropertyName("category")] string Category,
    [property: JsonPropertyName("total_articles")] int TotalArticles,
    [property: JsonPropertyName("avg_score")] double AverageScore,
    [property: JsonPropertyName("top_keywords")] IReadOnlyList<KeywordOccurrenceResponse> TopKeywords,
    [property: JsonPropertyName("top_sources")] IReadOnlyList<KeywordSourceCountResponse> TopSources,
    [property: JsonPropertyName("recent_articles")] IReadOnlyList<KeywordRecentArticleResponse> RecentArticles)
{
    public static KeywordCategoryDetailsResponse From(KeywordCategoryDetails result) => new(
        result.Category,
        result.TotalArticles,
        result.AverageScore,
        result.TopKeywords.Select(KeywordOccurrenceResponse.From).ToArray(),
        result.TopSources.Select(KeywordSourceCountResponse.From).ToArray(),
        result.RecentArticles.Select(KeywordRecentArticleResponse.From).ToArray());
}

public sealed record KeywordRecategorizationResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("changed")] int Changed)
{
    public static KeywordRecategorizationResponse From(KeywordRecategorizationResult result) =>
        new("ok", result.Total, result.Changed);
}
