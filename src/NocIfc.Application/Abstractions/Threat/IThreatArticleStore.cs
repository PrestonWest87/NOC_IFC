using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface IThreatArticleStore
{
    Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken);
    Task<ThreatArticlePage> GetPageAsync(
        string category,
        string categoryFilter,
        int page,
        int pageSize,
        string? searchTerm,
        int minimumScore,
        CancellationToken cancellationToken);
    Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken);
    Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(IReadOnlyList<int> articleIds, CancellationToken cancellationToken);
    Task TogglePinAsync(int articleId, CancellationToken cancellationToken);
    Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken);
}
