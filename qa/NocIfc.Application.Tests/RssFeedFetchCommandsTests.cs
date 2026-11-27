using System.Globalization;
using System.Text;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RssFeedFetchCommandsTests
{
    [Fact]
    public async Task FetchesOnlyActiveFeedsSkipsKnownLinksAndScoresExtractsAndPersistsNewArticles()
    {
        var published = DateTimeOffset.UtcNow.ToString("r", CultureInfo.InvariantCulture);
        var feed = Encoding.UTF8.GetBytes($"""
            <rss><channel>
              <item><title>Ransomware gang exploits CVE-2026-12345</title><link>https://source.example.test/new</link><description>Attack at 1.2.3.4</description><pubDate>{published}</pubDate></item>
              <item><title>Known article</title><link>https://source.example.test/known</link></item>
              <item><title>Duplicate in feed</title><link>https://source.example.test/new</link></item>
            </channel></rss>
            """);
        var settings = new StubRssSettingsStore(new RssSettingsCatalog(
            [new KeywordDirectoryEntry(2, "ransomware", 90), new KeywordDirectoryEntry(1, "cve", 70)],
            [
                new FeedSourceEntry(1, "https://source.example.test/feed", "Threat Feed", true),
                new FeedSourceEntry(2, "https://failed.example.test/feed", "Failed Feed", true),
                new FeedSourceEntry(3, "https://inactive.example.test/feed", "Inactive Feed", false),
            ]));
        var client = new StubFeedClient(new Dictionary<string, byte[]?>(StringComparer.Ordinal)
        {
            ["https://source.example.test/feed"] = feed,
            ["https://failed.example.test/feed"] = null,
        });
        var store = new StubIngestionStore(["https://source.example.test/known"]);

        var result = await new RssFeedFetchCommands(settings, client, store).ExecuteAsync(CancellationToken.None);

        Assert.Equal(1, result.AddedCount);
        Assert.Equal(1, result.FailedFeeds);
        Assert.Equal(0, result.RemovedDuplicates);
        Assert.Equal(new[] { "https://source.example.test/feed", "https://failed.example.test/feed" }, client.RequestedUrls);
        var article = Assert.Single(store.Inserted);
        Assert.Equal("Threat Feed", article.Source);
        Assert.Equal("https://source.example.test/new", article.Link);
        Assert.Equal(100, article.Score);
        Assert.Equal("Cyber: Exploits & Vulns", article.Category);
        Assert.True(article.IsBubbled);
        Assert.Equal(new[] { "cve", "ransomware" }, article.KeywordsFound);
        Assert.Contains(article.Iocs, ioc => ioc.Type == "CVE" && ioc.Indicator == "CVE-2026-12345");
        Assert.Contains(article.Iocs, ioc => ioc.Type == "IPv4" && ioc.Indicator == "1.2.3.4");
        Assert.InRange(store.RecentLinksAfter, DateTime.UtcNow.AddDays(-7).AddSeconds(-2), DateTime.UtcNow.AddDays(-7).AddSeconds(1));
        Assert.InRange(store.DeduplicateAfter, DateTime.UtcNow.AddHours(-24).AddSeconds(-2), DateTime.UtcNow.AddHours(-24).AddSeconds(1));
    }

    private sealed class StubRssSettingsStore(RssSettingsCatalog catalog) : IRssSettingsStore
    {
        public Task<RssSettingsCatalog> GetCatalogAsync(CancellationToken cancellationToken) => Task.FromResult(catalog);
        public Task AddKeywordsAsync(IReadOnlyList<KeywordDirectoryEntry> keywords, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task AddFeedsAsync(IReadOnlyList<FeedSourceEntry> feeds, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<KeywordDirectoryEntry?> UpdateKeywordWeightAsync(int keywordId, int weight, CancellationToken cancellationToken) =>
            Task.FromResult<KeywordDirectoryEntry?>(null);
        public Task DeleteKeywordAsync(int keywordId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task DeleteFeedAsync(int feedId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubFeedClient(IReadOnlyDictionary<string, byte[]?> feeds) : IRssFeedClient
    {
        public List<string?> RequestedUrls { get; } = [];
        public Task<byte[]?> FetchAsync(string? url, CancellationToken cancellationToken)
        {
            RequestedUrls.Add(url);
            return Task.FromResult(url is not null && feeds.TryGetValue(url, out var content) ? content : null);
        }
    }

    private sealed class StubIngestionStore(IReadOnlyList<string> knownLinks) : IRssIngestionStore
    {
        public IReadOnlyList<RssArticleIngestCandidate> Inserted { get; private set; } = [];
        public DateTime RecentLinksAfter { get; private set; }
        public DateTime DeduplicateAfter { get; private set; }
        public Task<IReadOnlyList<string>> GetRecentLinksAsync(DateTime publishedAfterUtc, CancellationToken cancellationToken)
        {
            RecentLinksAfter = publishedAfterUtc;
            return Task.FromResult(knownLinks);
        }
        public Task<int> InsertArticlesAsync(IReadOnlyList<RssArticleIngestCandidate> articles, CancellationToken cancellationToken)
        {
            Inserted = articles;
            return Task.FromResult(articles.Count);
        }
        public Task<int> DeduplicateRecentArticlesAsync(DateTime publishedAfterUtc, CancellationToken cancellationToken)
        {
            DeduplicateAfter = publishedAfterUtc;
            return Task.FromResult(0);
        }
    }
}
