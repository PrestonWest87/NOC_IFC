namespace NocIfc.Application.Abstractions.Threat;

public sealed record KeywordAnalysisOverview(
    int TotalKeywords,
    int TotalArticles,
    double AverageWeight,
    int MaximumWeight,
    int MinimumWeight,
    int KeywordsUsed,
    int KeywordsUnused,
    int ArticlesWithKeywords,
    int ArticlesWithoutKeywords);

public sealed record KeywordAnalysisStat(
    int Id,
    string Word,
    int Weight,
    int TriggerCount,
    double AverageScoreContribution);

public sealed record KeywordCategoryDistribution(string Category, int Count, double AverageScore, double Percent);

public sealed record KeywordAnalysisTimelinePoint(
    string Date,
    int TotalArticles,
    int MatchedArticles,
    double MatchRate,
    double AverageScore);

public sealed record KeywordAnalysisArticle(
    int Id,
    string? Title,
    string? Source,
    string? Category,
    double? Score,
    DateTime? PublishedDate,
    IReadOnlyList<string> KeywordsFound);

public sealed record KeywordScoreBucket(string Bucket, int Count, string TopCategory);

public sealed record KeywordCategoryMatrix(
    IReadOnlyList<string> Categories,
    IReadOnlyList<string> Keywords,
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Matrix);

public sealed record KeywordOccurrence(string Word, int Count);

public sealed record KeywordSourceCount(string Source, int Count);

public sealed record KeywordRecentArticle(
    int Id,
    string? Title,
    string? Source,
    double? Score,
    DateTime? PublishedDate,
    IReadOnlyList<string> KeywordsFound);

public sealed record KeywordCategoryDetails(
    string Category,
    int TotalArticles,
    double AverageScore,
    IReadOnlyList<KeywordOccurrence> TopKeywords,
    IReadOnlyList<KeywordSourceCount> TopSources,
    IReadOnlyList<KeywordRecentArticle> RecentArticles);

public sealed record KeywordArticleForRecategorization(int Id, string? Title, string? Summary, string? Category);

public sealed record KeywordCategoryUpdate(int Id, string Category);

public sealed record KeywordRecategorizationResult(int Total, int Changed);

public interface IKeywordAnalysisStore
{
    Task<KeywordAnalysisOverview> GetOverviewAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordAnalysisStat>> GetKeywordStatsAsync(
        string sortBy,
        bool descending,
        string search,
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordCategoryDistribution>> GetCategoryDistributionAsync(
        int days,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordAnalysisTimelinePoint>> GetTimelineAsync(
        string keyword,
        int days,
        string interval,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordAnalysisArticle>> GetKeywordArticlesAsync(
        string keyword,
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordScoreBucket>> GetScoreDistributionAsync(
        int days,
        int bucketSize,
        CancellationToken cancellationToken);
    Task<KeywordCategoryMatrix> GetCategoryKeywordMatrixAsync(int topN, CancellationToken cancellationToken);
    Task<KeywordCategoryDetails> GetCategoryDetailsAsync(
        string category,
        int days,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<KeywordArticleForRecategorization>> GetRecategorizationBatchAsync(
        int afterId,
        int limit,
        CancellationToken cancellationToken);
    Task<int> UpdateArticleCategoriesAsync(
        IReadOnlyList<KeywordCategoryUpdate> updates,
        CancellationToken cancellationToken);
}
