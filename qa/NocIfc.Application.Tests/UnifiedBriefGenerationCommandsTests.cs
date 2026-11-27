using System.Text.Json;
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

public sealed class UnifiedBriefGenerationCommandsTests
{
    [Fact]
    public async Task GeneratesMapReduceBriefAndSavesItWithProgress()
    {
        var dashboardStore = new StubDashboardStore { Hazards = [Hazard("Tornado Warning", "Central NOC")] };
        var settings = new StubSettingsStore(ActiveSettings());
        var llm = new StubLlm(
            new LlmChatCompletionResult(true, "Cyber digest", null),
            new LlmChatCompletionResult(true, "Physical digest", null),
            new LlmChatCompletionResult(true, "Executive brief narrative.", null));
        var command = CreateCommand(
            dashboardStore,
            settings,
            llm,
            new StubExecutiveIntelStore(Inputs()),
            new StubInternalRiskStore(InternalSnapshot()));
        var progress = new List<UnifiedBriefGenerationProgress>();

        var result = await command.GenerateAsync(progress.Add, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(result.Brief, dashboardStore.SavedBrief);
        Assert.StartsWith("---\n**OSINT CORRELATION DISCLAIMER:**", result.Brief);
        Assert.Contains("Executive brief narrative.", result.Brief);
        Assert.Equal(3, llm.Calls.Count);
        Assert.Contains("APT29 targets Arkansas utility", llm.Calls[0].Messages[1].Content);
        Assert.Contains("CVE-2026-1234", llm.Calls[0].Messages[1].Content);
        Assert.Contains("Tornado Warning", llm.Calls[1].Messages[1].Content);
        Assert.Contains("router-1 (NX-OS): 2 Matches", llm.Calls[2].Messages[1].Content);
        Assert.Contains("Global OSINT Risk Level:", llm.Calls[2].Messages[1].Content);
        Assert.Equal("complete", progress[^1].Stage);
        Assert.Equal(100, progress[^1].Percent);
        Assert.Equal(new[] { "cyber_map", "phys_map", "synthesizing", "complete" },
            progress.Where(item => item.Stage is "cyber_map" or "phys_map" or "synthesizing" or "complete")
                .Select(item => item.Stage).Distinct().ToArray());
    }

    [Fact]
    public async Task DoesNotSaveDisabledOrFailedMapGeneration()
    {
        var dashboardStore = new StubDashboardStore();
        var disabledLlm = new StubLlm();
        var disabled = CreateCommand(
            dashboardStore,
            new StubSettingsStore(ActiveSettings() with { IsActive = false }),
            disabledLlm,
            new StubExecutiveIntelStore(Inputs()),
            new StubInternalRiskStore(InternalSnapshot()));
        var disabledProgress = new List<UnifiedBriefGenerationProgress>();
        var disabledResult = await disabled.GenerateAsync(disabledProgress.Add, CancellationToken.None);
        Assert.False(disabledResult.Success);
        Assert.Equal("AI is currently disabled in settings.", disabledResult.Message);
        Assert.Equal("error", disabledProgress[^1].Stage);
        Assert.Null(dashboardStore.SavedBrief);
        Assert.Empty(disabledLlm.Calls);

        var failedLlm = new StubLlm(new LlmChatCompletionResult(false, null, "offline"));
        var failed = CreateCommand(
            dashboardStore,
            new StubSettingsStore(ActiveSettings()),
            failedLlm,
            new StubExecutiveIntelStore(Inputs()),
            new StubInternalRiskStore(InternalSnapshot()));
        var failedProgress = new List<UnifiedBriefGenerationProgress>();
        var failedResult = await failed.GenerateAsync(failedProgress.Add, CancellationToken.None);
        Assert.False(failedResult.Success);
        Assert.Equal("Unified brief cyber evidence could not be processed.", failedResult.Message);
        Assert.Equal("error", failedProgress[^1].Stage);
        Assert.Null(dashboardStore.SavedBrief);
    }

    private static UnifiedBriefGenerationCommands CreateCommand(
        StubDashboardStore dashboard,
        StubSettingsStore settings,
        StubLlm llm,
        StubExecutiveIntelStore intel,
        StubInternalRiskStore internalRisk) => new(
        new ExecutiveIntelQueries(intel),
        new InternalRiskQueries(internalRisk),
        new CisaKevQueries(new StubCisaKevStore()),
        new DashboardQueries(dashboard),
        new ThreatStatusQueries(new StubThreatStatusStore()),
        dashboard,
        settings,
        llm);

    private static ExecutiveIntelInputs Inputs() => new(
        new RiskScoringSettings("auto", null, null, null, null, null, null, null, null, 0, 0, 3, 3),
        [],
        [Article(1, "APT29 targets Arkansas utility", "Grid access activity", "Cyber: Malware & Threats", "Threat Intel")],
        [Article(1, "APT29 targets Arkansas utility", "Grid access activity", "Cyber: Malware & Threats", "Threat Intel")],
        [Article(2, "Arkansas substation threat", "Risk to the power grid", "Physical Security & Crime", "Local News")],
        [],
        [],
        0);

    private static ThreatArticle Article(int id, string title, string summary, string category, string source) => new(
        id, title, null, summary, DateTime.UtcNow, source, 90, category, [], false, null,
        null, null, false, DateTime.UtcNow, null, null, null, null);

    private static DashboardRegionalHazard Hazard(string title, string location) => new(
        1, "hazard-1", "Tornado Warning", "Severe", title, "Rotating storm", location,
        DateTime.UtcNow, DateTime.UtcNow, "active", null, null, null, DateTime.UtcNow.AddHours(1),
        null, "Alert", null, "state", "county");

    private static InternalRiskSnapshotEntry InternalSnapshot()
    {
        using var hardware = JsonDocument.Parse("[{\"Identifier\":\"router-1\",\"OS\":\"NX-OS\",\"OSINT Threat Matches\":2,\"Top Threat Reference\":\"CVE-2026-1234\"}]");
        using var software = JsonDocument.Parse("[]");
        return new InternalRiskSnapshotEntry(
            1, DateTime.UtcNow, 50, "ORANGE", 2, 2, 1,
            hardware.RootElement.Clone(), software.RootElement.Clone(), "auto");
    }

    private static AiSmtpSettings ActiveSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 128_000,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubDashboardStore : IOperationalDashboardStore
    {
        public IReadOnlyList<DashboardRegionalHazard> Hazards { get; init; } = [];
        public string? SavedBrief { get; private set; }
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new DashboardMetrics(0, 0, 0, 0));
        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult(Hazards);
        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyThreatScoreEntry>>([]);
        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<DashboardBriefSnapshot?>(null);
        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken)
        {
            SavedBrief = content;
            return Task.FromResult(true);
        }
    }

    private sealed class StubExecutiveIntelStore(ExecutiveIntelInputs inputs) : IExecutiveIntelStore
    {
        public Task<ExecutiveIntelInputs> GetInputsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(inputs);
        public Task SaveDailyThreatScoreAsync(
            DateTime recordDateUtc, int cyberPoints, int physicalPoints, double cyberBaseline, double physicalBaseline,
            CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubInternalRiskStore(InternalRiskSnapshotEntry? snapshot) : IInternalRiskStore
    {
        public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) => Task.FromResult(snapshot);
        public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<InternalRiskHistoryPoint>>([]);
    }

    private sealed class StubCisaKevStore : ICisaKevStore
    {
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CisaKevEntry>>(
                [new CisaKevEntry(1, "CVE-2026-1234", "Vendor", "Router", "Command injection", DateTime.UtcNow, null, null, null)]);
    }

    private sealed class StubThreatStatusStore : IThreatStatusStore
    {
        public Task<IReadOnlyList<CloudOutageEntry>> GetCloudOutagesAsync(bool activeOnly, DateTime updatedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CloudOutageEntry>>(
                [new CloudOutageEntry(1, "Azure", "Compute", "Regional disruption", null, null, false, DateTime.UtcNow, null, null)]);
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
