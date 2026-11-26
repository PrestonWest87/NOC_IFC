using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface IRssSettingsStore
{
    Task<RssSettingsCatalog> GetCatalogAsync(CancellationToken cancellationToken);
    Task AddKeywordsAsync(IReadOnlyList<KeywordDirectoryEntry> keywords, CancellationToken cancellationToken);
    Task AddFeedsAsync(IReadOnlyList<FeedSourceEntry> feeds, CancellationToken cancellationToken);
    Task<KeywordDirectoryEntry?> UpdateKeywordWeightAsync(int keywordId, int weight, CancellationToken cancellationToken);
    Task DeleteKeywordAsync(int keywordId, CancellationToken cancellationToken);
    Task DeleteFeedAsync(int feedId, CancellationToken cancellationToken);
}
