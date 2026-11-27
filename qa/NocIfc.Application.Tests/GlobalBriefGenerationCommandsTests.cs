using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class GlobalBriefGenerationCommandsTests
{
    [Fact]
    public async Task FiltersMapsClassifiesAndSavesGlobalBrief()
    {
        var usArticle = Article(1, "APT29 targets Texas power grid", "Attack activity observed.", "Cyber: Malware & Threats");
        var internationalArticle = Article(2, "Ransomware attacks European hospitals", "Healthcare disruption reported.", "Cyber: Malware & Threats");
        var executive = new StubExecutiveIntelStore(Inputs(usArticle), [usArticle, internationalArticle]);
        var dashboard = new StubDashboardStore { Hazards = [Hazard("Tornado Warning", "Pulaski County")] };
        var settings = new StubSettingsStore(ActiveSettings());
        var llm = new StubLlm(
            new LlmChatCompletionResult(true, "- APT29 targets Texas power grid using malware CVE-2026-1234\n- Ransomware attacks European hospitals", null),
            new LlmChatCompletionResult(true, "TYPE: Tornado Warning; LOCATION: Pulaski County", null),
            new LlmChatCompletionResult(true, "A targeted actor and vulnerability affect US power infrastructure while ransomware threatens international healthcare.", null));
        var command = CreateCommand(
            executive,
            dashboard,
            settings,
            llm);
        var progress = new List<BriefGenerationProgress>();

        var result = await command.GenerateAsync(progress.Add, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(result.Brief, dashboard.SavedGlobalBrief);
        Assert.Contains("US Critical Infrastructure Threat Assessment", result.Brief);
        Assert.Contains("Electric/Power Grid", result.Brief);
        Assert.Contains("APT29", result.Brief);
        Assert.Contains("CVE-2026-1234", result.Brief);
        Assert.Contains("Global Threat Landscape", result.Brief);
        Assert.Contains("Tornado Warning", result.Brief);
        Assert.Contains("US power infrastructure", result.Brief);
        Assert.Equal(3, llm.Calls.Count);
        Assert.Equal("complete", progress[^1].Stage);
        Assert.Equal(100, progress[^1].Percent);
    }

    [Fact]
    public async Task DoesNotPersistBriefWhenMapCallsFail()
    {
        var article = Article(1, "APT29 targets a power grid", "Threat activity.", "Cyber: Malware & Threats");
        var dashboard = new StubDashboardStore();
        var llm = new StubLlm(new LlmChatCompletionResult(false, null, "offline"));
        var command = CreateCommand(
            new StubExecutiveIntelStore(Inputs(article), [article]), dashboard, new StubSettingsStore(ActiveSettings()), llm);
        var progress = new List<BriefGenerationProgress>();

        var result = await command.GenerateAsync(progress.Add, CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("Intelligence processing failed.", result.Message);
        Assert.Null(dashboard.SavedGlobalBrief);
        Assert.Equal("error", progress[^1].Stage);
    }

    private static GlobalBriefGenerationCommands CreateCommand(
        StubExecutiveIntelStore executive,
        StubDashboardStore dashboard,
        StubSettingsStore settings,
        StubLlm llm) => new(
        new ExecutiveIntelQueries(executive),
        new StubKevStore(),
        new DashboardQueries(dashboard),
        new ThreatStatusQueries(new StubThreatStatusStore()),
        dashboard,
        settings,
        llm);

    private static ExecutiveIntelInputs Inputs(ThreatArticle article) => new(
        new RiskScoringSettings("auto", null, null, null, null, null, null, null, null, 0, 0, 3, 3),
        [],
        [article],
        [article],
        [], [], [], 0);

    private static ThreatArticle Article(int id, string title, string summary, string category) => new(
        id, title, $"https://example.test/{id}", summary, DateTime.UtcNow, "Threat Intel", 85, category,
        [], false, null, null, null, false, DateTime.UtcNow, null, null, null, null);

    private static DashboardRegionalHazard Hazard(string title, string location) => new(
        1, "hazard-1", "Tornado Warning", "Severe", title, "Storm details", location,
        DateTime.UtcNow, DateTime.UtcNow, "active", null, null, null, DateTime.UtcNow.AddHours(1),
        null, "Alert", null, "state", "county");

    private static AiSmtpSettings ActiveSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 128_000,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubExecutiveIntelStore(ExecutiveIntelInputs inputs, IReadOnlyList<ThreatArticle>? scored = null) : IExecutiveIntelStore
    {
        public Task<ExecutiveIntelInputs> GetInputsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(inputs);
        public Task<IReadOnlyList<ThreatArticle>> GetRecentScoredArticlesAsync(DateTime sinceUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>(scored ?? []);
        public Task SaveDailyThreatScoreAsync(
            DateTime recordDateUtc, int cyberPoints, int physicalPoints, double cyberBaseline, double physicalBaseline,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubDashboardStore : IOperationalDashboardStore
    {
        public IReadOnlyList<DashboardRegionalHazard> Hazards { get; init; } = [];
        public string? SavedGlobalBrief { get; private set; }
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new DashboardMetrics(0, 0, 0, 0));
        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult(Hazards);
        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyThreatScoreEntry>>([]);
        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<DashboardBriefSnapshot?>(null);
        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken)
        {
            SavedGlobalBrief = content;
            return Task.FromResult(true);
        }
        public Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }

    private sealed class StubKevStore : ICisaKevStore
    {
        public Task<int> InsertMissingAsync(IReadOnlyList<CisaKevEntry> entries, CancellationToken cancellationToken) =>
            Task.FromResult(0);
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CisaKevEntry>>(
                [new CisaKevEntry(1, "CVE-2026-1234", "Vendor", "Router", "Command injection", DateTime.UtcNow, null, null, null)]);
    }

    private sealed class StubThreatStatusStore : IThreatStatusStore
    {
        public Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(bool activeOnly, DateTime updatedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CloudOutageEntry>>([]);
        public Task<IReadOnlyList<CrimeIncidentEntry>> GetRecentCrimesAsync(double maxDistance, DateTime occurredAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CrimeIncidentEntry>>([]);
        public Task<Microsoft365StatusSnapshot> GetMicrosoft365StatusAsync(DateTime updatedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new Microsoft365StatusSnapshot(null, null, null, []));
    }

    private sealed class StubSettingsStore(AiSmtpSettings? settings) : IAiSmtpSettingsStore
    {
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) => Task.FromResult("saved-key");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubLlm(params LlmChatCompletionResult[] responses) : ILlmChatCompletionClient
    {
        public List<(IReadOnlyList<LlmChatMessage> Messages, double Temperature)> Calls { get; } = [];
        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add((messages, temperature));
            return Task.FromResult(responses[Calls.Count - 1]);
        }
    }
}
