using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class KeywordAnalysisQueries(IKeywordAnalysisStore store)
{
    public Task<KeywordAnalysisOverview> GetOverviewAsync(CancellationToken cancellationToken) =>
        store.GetOverviewAsync(cancellationToken);

    public Task<IReadOnlyList<KeywordAnalysisStat>> GetKeywordStatsAsync(
        string sortBy,
        string order,
        string search,
        int limit,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 500) throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 500.");
        if (search.Length > 200) throw new ArgumentException("search must be 200 characters or fewer.", nameof(search));
        if (sortBy is not ("weight" or "trigger_count" or "avg_score_contribution")) sortBy = "trigger_count";
        return store.GetKeywordStatsAsync(sortBy, order == "desc", search, limit, cancellationToken);
    }

    public Task<IReadOnlyList<KeywordCategoryDistribution>> GetCategoryDistributionAsync(
        int days,
        CancellationToken cancellationToken)
    {
        ValidateDays(days);
        return store.GetCategoryDistributionAsync(days, cancellationToken);
    }

    public Task<IReadOnlyList<KeywordAnalysisTimelinePoint>> GetTimelineAsync(
        string? keyword,
        int days,
        string interval,
        CancellationToken cancellationToken)
    {
        ValidateDays(days);
        if (interval is not ("day" or "week")) throw new ArgumentException("interval must be day or week.", nameof(interval));
        if (keyword?.Length > 200) throw new ArgumentException("keyword must be 200 characters or fewer.", nameof(keyword));
        return store.GetTimelineAsync(keyword ?? "", days, interval, cancellationToken);
    }

    public Task<IReadOnlyList<KeywordAnalysisArticle>> GetKeywordArticlesAsync(
        string? keyword,
        int limit,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(keyword)) throw new ArgumentException("keyword is required.", nameof(keyword));
        if (keyword.Length > 200) throw new ArgumentException("keyword must be 200 characters or fewer.", nameof(keyword));
        if (limit is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 100.");
        return store.GetKeywordArticlesAsync(keyword, limit, cancellationToken);
    }

    public Task<IReadOnlyList<KeywordScoreBucket>> GetScoreDistributionAsync(
        int days,
        int bucketSize,
        CancellationToken cancellationToken)
    {
        ValidateDays(days);
        if (bucketSize is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(bucketSize), "bucket_size must be between 1 and 100.");
        return store.GetScoreDistributionAsync(days, bucketSize, cancellationToken);
    }

    public Task<KeywordCategoryMatrix> GetCategoryKeywordMatrixAsync(int topN, CancellationToken cancellationToken)
    {
        if (topN is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(topN), "top_n must be between 1 and 100.");
        return store.GetCategoryKeywordMatrixAsync(topN, cancellationToken);
    }

    public Task<KeywordCategoryDetails> GetCategoryDetailsAsync(
        string? category,
        int days,
        CancellationToken cancellationToken)
    {
        ValidateDays(days);
        if (string.IsNullOrWhiteSpace(category)) throw new ArgumentException("category is required.", nameof(category));
        if (category.Length > 255) throw new ArgumentException("category must be 255 characters or fewer.", nameof(category));
        return store.GetCategoryDetailsAsync(category, days, cancellationToken);
    }

    private static void ValidateDays(int days)
    {
        if (days is < 0 or > 3650) throw new ArgumentOutOfRangeException(nameof(days), "days must be between 0 and 3650.");
    }
}

public sealed class KeywordAnalysisCommands(IKeywordAnalysisStore store)
{
    private const int BatchSize = 250;

    public async Task<KeywordRecategorizationResult> RecategorizeAsync(CancellationToken cancellationToken)
    {
        var total = 0;
        var changed = 0;
        var afterId = 0;
        while (true)
        {
            var batch = await store.GetRecategorizationBatchAsync(afterId, BatchSize, cancellationToken);
            if (batch.Count == 0) break;

            var updates = batch
                .Select(article => new KeywordCategoryUpdate(
                    article.Id,
                    ArticleCategorizer.CategorizeText($"{article.Title ?? ""} {article.Summary ?? ""}")))
                .Where((update, index) => !string.Equals(update.Category, batch[index].Category, StringComparison.Ordinal))
                .ToArray();
            if (updates.Length > 0)
            {
                changed += await store.UpdateArticleCategoriesAsync(updates, cancellationToken);
            }

            total += batch.Count;
            afterId = batch[^1].Id;
        }
        return new KeywordRecategorizationResult(total, changed);
    }
}
