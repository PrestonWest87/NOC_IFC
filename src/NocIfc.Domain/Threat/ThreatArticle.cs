namespace NocIfc.Domain.Threat;

public sealed record ThreatArticle(
    int Id,
    string? Title,
    string? Link,
    string? Summary,
    DateTime? PublishedDate,
    string? Source,
    double? Score,
    string? Category,
    IReadOnlyList<string>? KeywordsFound,
    bool? IsBubbled,
    string? StoryGroup,
    string? FullContent,
    string? AiBluf,
    bool? IsPinned,
    DateTime? IngestedAt,
    string? EnrichmentStatus,
    int? EnrichmentAttempts,
    string? LastEnrichmentError,
    DateTime? LastEnrichedAt);

public sealed record ThreatArticlePage(
    IReadOnlyList<ThreatArticle> Items,
    int Total,
    int TotalPages,
    int Page);

public sealed record ThreatArticleKeyword(string Word, int Weight);

public sealed record ThreatArticleIoc(string? IndicatorType, string? IndicatorValue, string? Context);

public sealed record ThreatArticleDetail(
    ThreatArticle Article,
    IReadOnlyList<ThreatArticleKeyword> KeywordsWithWeights,
    int TotalKeywordScore,
    IReadOnlyList<ThreatArticleIoc> Iocs);
