using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface IThreatHuntingStore
{
    Task<IReadOnlyList<ExtractedIocEntry>> GetRecentIocsAsync(
        DateTime detectedAfterUtc,
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<ThreatArticle>> SearchArticlesAsync(
        DateTime publishedAfterUtc,
        IReadOnlyList<string> terms,
        int limit,
        CancellationToken cancellationToken);
    Task<PagedElasticEvents> GetElasticEventsAsync(
        DateTime createdAfterUtc,
        int page,
        int pageSize,
        int hoursBack,
        CancellationToken cancellationToken);
}
