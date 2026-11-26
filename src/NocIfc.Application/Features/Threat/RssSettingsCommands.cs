using System.Globalization;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class RssSettingsCommands(IRssSettingsStore settings)
{
    public Task<RssSettingsCatalog> GetAsync(CancellationToken cancellationToken) =>
        settings.GetCatalogAsync(cancellationToken);

    public Task AddBulkKeywordsAsync(string rawText, CancellationToken cancellationToken)
    {
        var keywords = new List<KeywordDirectoryEntry>();
        foreach (var line in rawText.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            var parts = line.Split(',');
            var word = parts[0].Trim().ToLowerInvariant();
            var rawWeight = parts.Length > 1 ? parts[1].Trim() : "10";
            var weight = int.TryParse(rawWeight, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                && parsed is >= 1 and <= 100
                    ? parsed
                    : 10;
            keywords.Add(new KeywordDirectoryEntry(0, word, weight));
        }
        return settings.AddKeywordsAsync(keywords, cancellationToken);
    }

    public Task AddBulkFeedsAsync(string rawText, CancellationToken cancellationToken)
    {
        var feeds = new List<FeedSourceEntry>();
        foreach (var line in rawText.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            var parts = line.Split(',');
            feeds.Add(new FeedSourceEntry(
                0,
                parts[0].Trim(),
                parts.Length > 1 ? parts[1].Trim() : "New Feed",
                true));
        }
        return settings.AddFeedsAsync(feeds, cancellationToken);
    }

    public async Task<KeywordDirectoryEntry> UpdateKeywordWeightAsync(
        int keywordId,
        int weight,
        CancellationToken cancellationToken)
    {
        if (weight is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(weight), "weight must be between 1 and 100.");
        }
        return await settings.UpdateKeywordWeightAsync(keywordId, weight, cancellationToken)
            ?? throw new KeyNotFoundException($"Keyword with id {keywordId} not found.");
    }

    public Task DeleteKeywordAsync(int keywordId, CancellationToken cancellationToken) =>
        settings.DeleteKeywordAsync(keywordId, cancellationToken);

    public Task DeleteFeedAsync(int feedId, CancellationToken cancellationToken) =>
        settings.DeleteFeedAsync(feedId, cancellationToken);
}
