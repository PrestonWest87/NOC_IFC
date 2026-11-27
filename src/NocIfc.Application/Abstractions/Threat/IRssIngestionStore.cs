using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface IRssIngestionStore
{
    Task<IReadOnlyList<string>> GetRecentLinksAsync(DateTime publishedAfterUtc, CancellationToken cancellationToken);
    Task<int> InsertArticlesAsync(IReadOnlyList<RssArticleIngestCandidate> articles, CancellationToken cancellationToken);
    Task<int> DeduplicateRecentArticlesAsync(DateTime publishedAfterUtc, CancellationToken cancellationToken);
}
