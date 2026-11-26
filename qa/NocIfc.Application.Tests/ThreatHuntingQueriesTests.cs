using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ThreatHuntingQueriesTests
{
    [Fact]
    public async Task GroupsRepeatedCvesAndLeavesOtherIndicatorsAsIndividualRows()
    {
        var now = DateTime.UtcNow;
        var store = new StubStore
        {
            Iocs =
            [
                new(1, "CVE", "CVE-2026-1234", null, now, "https://example.test/one", "First source"),
                new(2, "IPv4", "192.0.2.10", "Host indicator", now.AddMinutes(-1), null, null),
                new(3, "CVE", "CVE-2026-1234", "Second context", now.AddMinutes(-2), "https://example.test/two", "Second source"),
            ],
        };
        var queries = new ThreatHuntingQueries(store);

        var result = await queries.GetIocsAsync(3, 1000, CancellationToken.None);

        Assert.Equal("IPv4", result[0].Type);
        Assert.Equal("192.0.2.10", result[0].Indicator);
        Assert.Equal("Unknown", result[0].SourceArticle);
        Assert.Equal("CVE", result[1].Type);
        Assert.Equal("Context unavailable.", result[1].Context);
        Assert.Equal(2, result[1].ArticleCount);
        Assert.Equal(new[] { "First source", "Second source" }, result[1].Sources.Select(source => source.Title));
        Assert.InRange(store.IocCutoffDays, 3, 3);
        Assert.Equal(1000, store.IocLimit);
    }

    [Fact]
    public async Task ParsesQuotedSearchTermsAndRejectsUnsafeSearchBounds()
    {
        var store = new StubStore();
        var queries = new ThreatHuntingQueries(store);
        await queries.SearchArticlesAsync("\"Volt Typhoon\", LockBit; volt", 14, CancellationToken.None);

        Assert.Equal(new[] { "Volt Typhoon", "LockBit", "volt" }, store.SearchTerms);
        Assert.Equal(30, store.SearchLimit);
        Assert.Equal(14, store.SearchDays);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            queries.SearchArticlesAsync("\"unclosed", 14, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            queries.SearchArticlesAsync(new string('x', 501), 14, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            queries.SearchArticlesAsync("ransomware", 31, CancellationToken.None));
    }

    [Fact]
    public void BuildsOnlyValidatedOsintPivotUrls()
    {
        var queries = new ThreatHuntingQueries(new StubStore());
        Assert.Equal(
            "https://www.virustotal.com/gui/file/0123456789abcdef0123456789abcdef",
            queries.GetOsintPivotLink("MD5", "0123456789abcdef0123456789abcdef"));
        Assert.Equal("https://www.shodan.io/host/192.0.2.10", queries.GetOsintPivotLink("IPv4", "192.0.2.10"));
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2026-1234", queries.GetOsintPivotLink("CVE", "cve-2026-1234"));
        Assert.Equal("https://attack.mitre.org/techniques/T1234/001", queries.GetOsintPivotLink("MITRE ATT&CK", "T1234.001"));
        Assert.Null(queries.GetOsintPivotLink("IPv4", "127.0.0.1/anything"));
        Assert.Null(queries.GetOsintPivotLink("SHA256", "not-a-hash"));
    }

    [Fact]
    public async Task EnforcesElasticPaginationBoundsAndReturnsPageShape()
    {
        var store = new StubStore
        {
            ElasticPage = new PagedElasticEvents([], 12, 2, 10, 48),
        };
        var queries = new ThreatHuntingQueries(store);
        var page = await queries.GetElasticEventsAsync(48, 2, 10, CancellationToken.None);
        Assert.Equal(12, page.Total);
        Assert.Equal(2, page.Page);
        Assert.Equal(48, page.HoursBack);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetElasticEventsAsync(0, 1, 10, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetElasticEventsAsync(24, 0, 10, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetElasticEventsAsync(24, 1, 501, CancellationToken.None));
    }

    private sealed class StubStore : IThreatHuntingStore
    {
        public IReadOnlyList<ExtractedIocEntry> Iocs { get; init; } = [];
        public IReadOnlyList<string> SearchTerms { get; private set; } = [];
        public int IocLimit { get; private set; }
        public int IocCutoffDays { get; private set; }
        public int SearchLimit { get; private set; }
        public int SearchDays { get; private set; }
        public PagedElasticEvents ElasticPage { get; init; } = new([], 0, 1, 100, 24);

        public Task<IReadOnlyList<ExtractedIocEntry>> GetRecentIocsAsync(
            DateTime detectedAfterUtc,
            int limit,
            CancellationToken cancellationToken)
        {
            IocLimit = limit;
            IocCutoffDays = (int)Math.Round((DateTime.UtcNow - detectedAfterUtc).TotalDays);
            return Task.FromResult(Iocs);
        }

        public Task<IReadOnlyList<ThreatArticle>> SearchArticlesAsync(
            DateTime publishedAfterUtc,
            IReadOnlyList<string> terms,
            int limit,
            CancellationToken cancellationToken)
        {
            SearchTerms = terms;
            SearchLimit = limit;
            SearchDays = (int)Math.Round((DateTime.UtcNow - publishedAfterUtc).TotalDays);
            return Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        }

        public Task<PagedElasticEvents> GetElasticEventsAsync(
            DateTime createdAfterUtc,
            int page,
            int pageSize,
            int hoursBack,
            CancellationToken cancellationToken) => Task.FromResult(ElasticPage);
    }
}
