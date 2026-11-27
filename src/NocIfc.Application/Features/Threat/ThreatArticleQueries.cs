using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class ThreatArticleQueries(IThreatArticleStore articles)
{
    private static readonly HashSet<string> Categories = new(["live", "pinned", "low", "search"], StringComparer.Ordinal);

    public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) =>
        articles.GetPinnedAsync(cancellationToken);

    public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 100.");
        }
        return articles.GetLiveAsync(limit, DateTime.UtcNow.AddDays(-1), cancellationToken);
    }

    public Task<ThreatArticlePage> GetPageAsync(
        string category,
        string categoryFilter,
        int page,
        int pageSize,
        string? searchTerm,
        int minimumScore,
        CancellationToken cancellationToken)
    {
        if (!Categories.Contains(category))
        {
            throw new ArgumentException("category must be live, pinned, low, or search.");
        }
        if (page < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(page), "page must be at least 1.");
        }
        if (pageSize is < 5 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(pageSize), "page_size must be between 5 and 100.");
        }
        if (minimumScore < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(minimumScore), "min_score must be non-negative.");
        }
        return articles.GetPageAsync(
            category, categoryFilter, page, pageSize, searchTerm, minimumScore, cancellationToken);
    }

    public Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken) =>
        articles.GetDetailAsync(articleId, cancellationToken);

    public Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(
        IReadOnlyList<int> articleIds,
        CancellationToken cancellationToken)
    {
        if (articleIds.Count > 100 || articleIds.Any(id => id <= 0))
        {
            throw new ArgumentException("article_ids must contain at most 100 positive integers.", nameof(articleIds));
        }
        return articles.GetByIdsAsync(articleIds.Distinct().ToArray(), cancellationToken);
    }

    public Task TogglePinAsync(int articleId, CancellationToken cancellationToken) =>
        articles.TogglePinAsync(articleId, cancellationToken);

    public async Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken)
    {
        if (amount is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(amount), "amount must be between 1 and 100.");
        }
        await articles.BoostScoreAsync(articleId, amount, cancellationToken);
    }
}
