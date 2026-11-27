using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class InternalRiskScoringCommandsTests
{
    [Fact]
    public async Task CorrelatesDeduplicatedAssetsWithRecentArticlesAndKevsThenPersistsSnapshot()
    {
        var inventory = new InternalRiskAssetInventory(
        [
            new InternalRiskHardwareAsset("192.0.2.1", "Stale Firewall", "PAN-OS", null, "Palo Alto", "10.0"),
            new InternalRiskHardwareAsset("192.0.2.1", "Firewall-1", "PAN-OS", null, "Palo Alto", "11.0"),
        ],
        [
            new InternalRiskSoftwareAsset("Windows Server 2022"),
            new InternalRiskSoftwareAsset(" windows server 2022 "),
            new InternalRiskSoftwareAsset("Nginx 1.25"),
            new InternalRiskSoftwareAsset("Office"),
            new InternalRiskSoftwareAsset(""),
        ]);
        var articles = new StubArticleStore(
        [
            Article(1, "Palo Alto PAN-OS 11.0 vulnerability", "Remote code execution exploit", 90),
            Article(2, "Windows Server 2022 remote code execution", "Critical vulnerability and exploit", 85),
            Article(3, "Office of the Mayor reports vulnerability", "Community calendar", 99),
        ]);
        var kev = new CisaKevEntry(
            1, "CVE-2026-7001", "Palo Alto Networks", "Palo Alto PAN-OS 11.0",
            "Remote code execution vulnerability", DateTime.UtcNow, "Security flaw", null, null);
        var store = new StubInternalRiskStore(inventory);
        var kevStore = new StubKevStore([kev]);
        var command = new InternalRiskScoringCommands(store, articles, kevStore, new StubRiskSettingsStore(AutoSettings()));

        var result = await command.GenerateAndSaveAsync(CancellationToken.None);

        Assert.Equal(4, result.TotalAssets);
        Assert.Equal(1, result.TotalHardwareLoaded);
        Assert.Equal(3, result.TotalSoftwareLoaded);
        Assert.Equal(3, result.TotalOsintHits);
        Assert.Equal(3, result.CriticalOsintHits);
        Assert.Equal(5, result.AutoCriticality);
        Assert.Equal(3, result.AutoLethality);
        Assert.Equal(2, result.Score);
        Assert.Equal("YELLOW", result.RiskLevel);
        Assert.Equal(500, articles.RequestedLimit);
        Assert.InRange(articles.PublishedAfterUtc, DateTime.UtcNow.AddDays(-30).AddSeconds(-2), DateTime.UtcNow.AddDays(-30).AddSeconds(1));
        Assert.Equal(300, kevStore.RequestedLimit);
        Assert.Equal(DateTime.MinValue, kevStore.AddedAfterUtc);
        Assert.Equal(50, store.SavedSnapshot?.HardwareData[0].GetProperty("OSINT Risk Score").GetInt32());
        Assert.Equal("Firewall-1", store.SavedSnapshot?.HardwareData[0].GetProperty("Identifier").GetString());
        Assert.Equal(1, store.SavedSnapshot?.SoftwareData.GetArrayLength());
        Assert.Equal(25, store.SavedSnapshot?.SoftwareData[0].GetProperty("OSINT Risk Score").GetInt32());
    }

    [Fact]
    public async Task AppliesManualOverridesAndHybridOffsetOnlyInTheirModes()
    {
        var store = new StubInternalRiskStore(new InternalRiskAssetInventory(
            [new InternalRiskHardwareAsset("192.0.2.5", "Firewall", "PAN-OS", null, "Palo Alto", "11.0")], []));
        var articles = new StubArticleStore([Article(1, "Palo Alto PAN-OS 11.0 vulnerability", "Exploit", 90)]);
        var cves = new CisaKevEntry(1, "CVE-2026-7002", "Other Vendor", "Other Product", "Vulnerability", DateTime.UtcNow, "", null, null);

        var manual = await CreateCommand(store, articles, [cves],
            new RiskScoringSettings("manual", null, null, null, null, null, null, 4, 5, null, 3, 3, 3))
            .GenerateAndSaveAsync(CancellationToken.None);
        Assert.Equal(4, manual.Criticality);
        Assert.Equal(5, manual.Lethality);
        Assert.Equal(3, manual.Score);
        Assert.Equal("ORANGE", manual.RiskLevel);

        var hybrid = await CreateCommand(store, articles, [cves],
            new RiskScoringSettings("hybrid", null, null, null, null, null, null, 1, 1, null, 2, 3, 3))
            .GenerateAndSaveAsync(CancellationToken.None);
        Assert.Equal(5, hybrid.Criticality);
        Assert.Equal(3, hybrid.Lethality);
        Assert.Equal(4, hybrid.Score);
        Assert.Equal("ORANGE", hybrid.RiskLevel);
    }

    private static InternalRiskScoringCommands CreateCommand(
        StubInternalRiskStore store,
        StubArticleStore articles,
        IReadOnlyList<CisaKevEntry> cves,
        RiskScoringSettings settings) =>
        new(store, articles, new StubKevStore(cves), new StubRiskSettingsStore(settings));

    private static RiskScoringSettings AutoSettings() =>
        new("auto", null, null, null, null, null, null, null, null, null, null, 3, 3);

    private static ThreatArticle Article(int id, string title, string summary, int score) => new(
        id, title, $"https://example.test/{id}", summary, DateTime.UtcNow, "Threat Feed", score,
        "Cyber: Malware & Threats", [], false, null, null, null, false, DateTime.UtcNow, null, null, null, null);

    private sealed class StubInternalRiskStore(InternalRiskAssetInventory inventory) : IInternalRiskStore
    {
        public InternalRiskSnapshotEntry? SavedSnapshot { get; private set; }
        public Task<InternalRiskAssetInventory> GetAssetInventoryAsync(CancellationToken cancellationToken) => Task.FromResult(inventory);
        public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) => Task.FromResult(SavedSnapshot);
        public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<InternalRiskHistoryPoint>>([]);
        public Task SaveSnapshotAsync(InternalRiskSnapshotEntry snapshot, CancellationToken cancellationToken)
        {
            SavedSnapshot = snapshot;
            return Task.CompletedTask;
        }
    }

    private sealed class StubArticleStore(IReadOnlyList<ThreatArticle> recent) : IThreatArticleStore
    {
        public int RequestedLimit { get; private set; }
        public DateTime PublishedAfterUtc { get; private set; }
        public Task<IReadOnlyList<ThreatArticle>> GetRecentForInternalRiskAsync(
            int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken)
        {
            RequestedLimit = limit;
            PublishedAfterUtc = publishedAfterUtc;
            return Task.FromResult(recent);
        }
        public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<ThreatArticlePage> GetPageAsync(string category, string categoryFilter, int page, int pageSize, string? searchTerm, int minimumScore, CancellationToken cancellationToken) =>
            Task.FromResult(new ThreatArticlePage([], 0, 1, 1));
        public Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken) => Task.FromResult<ThreatArticleDetail?>(null);
        public Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(IReadOnlyList<int> articleIds, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<bool> SaveAiBlufAsync(int articleId, string bluf, CancellationToken cancellationToken) => Task.FromResult(true);
        public Task TogglePinAsync(int articleId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubKevStore(IReadOnlyList<CisaKevEntry> recent) : ICisaKevStore
    {
        public int RequestedLimit { get; private set; }
        public DateTime AddedAfterUtc { get; private set; }
        public Task<int> InsertMissingAsync(IReadOnlyList<CisaKevEntry> entries, CancellationToken cancellationToken) =>
            Task.FromResult(0);
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken)
        {
            RequestedLimit = limit;
            AddedAfterUtc = addedAfterUtc;
            return Task.FromResult(recent);
        }
    }

    private sealed class StubRiskSettingsStore(RiskScoringSettings settings) : IRiskScoringSettingsStore
    {
        public Task<RiskScoringSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<RiskScoringSettings?>(settings);
        public Task UpdateAsync(RiskScoringSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
