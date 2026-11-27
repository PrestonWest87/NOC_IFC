namespace NocIfc.Application.Abstractions.Threat;

public sealed record ArticleEnrichmentCandidate(int Id, string Link);

public interface IArticleEnrichmentStore
{
    Task<IReadOnlyList<ArticleEnrichmentCandidate>> ClaimPendingAsync(int limit, CancellationToken cancellationToken);
    Task SaveEnrichedAsync(int articleId, string fullContent, DateTime enrichedAtUtc, CancellationToken cancellationToken);
    Task SaveFailureAsync(int articleId, string error, CancellationToken cancellationToken);
}
