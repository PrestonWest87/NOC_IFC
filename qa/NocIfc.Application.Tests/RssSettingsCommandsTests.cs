using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RssSettingsCommandsTests
{
    [Fact]
    public async Task ParsesBulkListsAndValidatesKeywordWeightEdits()
    {
        var store = new StubStore();
        var commands = new RssSettingsCommands(store);

        await commands.AddBulkKeywordsAsync("Router, 50\nMalware, 0\nNo Weight\n", CancellationToken.None);
        await commands.AddBulkFeedsAsync("https://feeds.example/rss,Example Feed\nhttps://other.example/rss\n", CancellationToken.None);

        Assert.Equal(new (string Word, int? Weight)[] { ("router", 50), ("malware", 10), ("no weight", 10) },
            store.AddedKeywords.Select(keyword => (keyword.Word, keyword.Weight)));
        Assert.Equal(new (string? Url, string? Name)[] { ("https://feeds.example/rss", "Example Feed"), ("https://other.example/rss", "New Feed") },
            store.AddedFeeds.Select(feed => (feed.Url, feed.Name)));

        var updated = await commands.UpdateKeywordWeightAsync(4, 35, CancellationToken.None);
        Assert.Equal((int?)35, updated.Weight);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            commands.UpdateKeywordWeightAsync(4, 101, CancellationToken.None));
        await Assert.ThrowsAsync<KeyNotFoundException>(() =>
            commands.UpdateKeywordWeightAsync(404, 10, CancellationToken.None));
    }

    private sealed class StubStore : IRssSettingsStore
    {
        public List<KeywordDirectoryEntry> AddedKeywords { get; } = [];
        public List<FeedSourceEntry> AddedFeeds { get; } = [];

        public Task<RssSettingsCatalog> GetCatalogAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new RssSettingsCatalog([], []));

        public Task AddKeywordsAsync(IReadOnlyList<KeywordDirectoryEntry> keywords, CancellationToken cancellationToken)
        {
            AddedKeywords.AddRange(keywords);
            return Task.CompletedTask;
        }

        public Task AddFeedsAsync(IReadOnlyList<FeedSourceEntry> feeds, CancellationToken cancellationToken)
        {
            AddedFeeds.AddRange(feeds);
            return Task.CompletedTask;
        }

        public Task<KeywordDirectoryEntry?> UpdateKeywordWeightAsync(int keywordId, int weight, CancellationToken cancellationToken) =>
            Task.FromResult<KeywordDirectoryEntry?>(keywordId == 4 ? new KeywordDirectoryEntry(4, "router", weight) : null);

        public Task DeleteKeywordAsync(int keywordId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteFeedAsync(int feedId, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
