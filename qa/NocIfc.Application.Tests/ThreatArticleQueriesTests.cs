using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ThreatArticleQueriesTests
{
    [Fact]
    public async Task EnforcesArticleTriageFiltersBeforeCallingTheStore()
    {
        var store = new StubStore();
        var queries = new ThreatArticleQueries(store);

        await Assert.ThrowsAsync<ArgumentException>(() => queries.GetPageAsync(
            "unknown", "All", 1, 20, null, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetPageAsync(
            "live", "All", 0, 20, null, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetPageAsync(
            "live", "All", 1, 4, null, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetPageAsync(
            "live", "All", 1, 20, null, -1, CancellationToken.None));
        Assert.Equal(0, store.PageCalls);

        var page = await queries.GetPageAsync("search", "All", 2, 50, "router", 20, CancellationToken.None);
        Assert.Equal(1, store.PageCalls);
        Assert.Equal("search", store.Category);
        Assert.Equal(50, store.PageSize);
        Assert.Equal("router", store.SearchTerm);
        Assert.Equal(20, store.MinimumScore);
        Assert.Equal(3, page.Page);
    }

    private sealed class StubStore : IThreatArticleStore
    {
        public int PageCalls { get; private set; }
        public string? Category { get; private set; }
        public int PageSize { get; private set; }
        public string? SearchTerm { get; private set; }
        public int MinimumScore { get; private set; }

        public Task<ThreatArticlePage> GetPageAsync(
            string category,
            string categoryFilter,
            int page,
            int pageSize,
            string? searchTerm,
            int minimumScore,
            CancellationToken cancellationToken)
        {
            PageCalls++;
            Category = category;
            PageSize = pageSize;
            SearchTerm = searchTerm;
            MinimumScore = minimumScore;
            return Task.FromResult(new ThreatArticlePage([], 110, 3, 3));
        }

        public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);

        public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);

        public Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken) =>
            Task.FromResult<ThreatArticleDetail?>(null);

        public Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(
            IReadOnlyList<int> articleIds,
            CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);

        public Task TogglePinAsync(int articleId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
