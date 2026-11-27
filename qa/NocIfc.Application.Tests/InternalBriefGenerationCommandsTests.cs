using System.Text.Json;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class InternalBriefGenerationCommandsTests
{
    [Fact]
    public async Task CorrelatesAssetsAndPersistsACompleteInternalBrief()
    {
        var snapshot = Snapshot(
            "[{\"Identifier\":\"Firewall\",\"IP Address\":\"192.0.2.1\",\"OS\":\"PAN-OS 11\",\"OSINT Risk Score\":95,\"OSINT Threat Matches\":1,\"Top Threat Reference\":\"CVE-2026-1234\"}]",
            "[{\"Software Name\":\"Windows Server 2022\",\"risk_level\":\"HIGH\",\"OSINT Risk Score\":90,\"Active OSINT Matches\":1,\"Top Threat Reference\":\"CVE-2026-1234\"}]");
        var store = new StubDashboardStore();
        var llm = new StubLlm(
            new LlmChatCompletionResult(true, "Correlated Firewall exposure for CVE-2026-1234.", null),
            new LlmChatCompletionResult(true, "## Executive Internal Risk Assessment\nPatch the firewall.", null));
        var command = new InternalBriefGenerationCommands(
            new InternalRiskQueries(new StubInternalRiskStore(snapshot)), new StubKevStore(), store,
            new StubSettingsStore(ActiveSettings()), llm);
        var progress = new List<BriefGenerationProgress>();

        var result = await command.GenerateAsync(progress.Add, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(result.Brief, store.SavedInternalBrief);
        Assert.Contains("CVE-2026-1234", llm.Calls[0].Messages[1].Content);
        Assert.Contains("Firewall (192.0.2.1) | OS: PAN-OS 11", llm.Calls[0].Messages[1].Content);
        Assert.Contains("Windows Server 2022", llm.Calls[0].Messages[1].Content);
        Assert.Contains("Total Assets Monitored: 2", llm.Calls[1].Messages[0].Content);
        Assert.Contains("Internal CIS Risk Level: HIGH (Score: 75)", llm.Calls[1].Messages[0].Content);
        Assert.Equal(2, llm.Calls.Count);
        Assert.Equal("complete", progress[^1].Stage);
        Assert.Equal(100, progress[^1].Percent);
    }

    [Fact]
    public async Task RejectsMissingSnapshotDisabledAiAndFailedCorrelationWithoutSaving()
    {
        var store = new StubDashboardStore();
        var disabledLlm = new StubLlm();
        var missing = await new InternalBriefGenerationCommands(
                new InternalRiskQueries(new StubInternalRiskStore(null)), new StubKevStore(), store,
                new StubSettingsStore(ActiveSettings()), disabledLlm)
            .GenerateAsync(_ => { }, CancellationToken.None);
        Assert.Equal("No internal risk snapshot available. Trigger an internal risk calculation first.", missing.Message);

        var snapshot = Snapshot("[{\"Identifier\":\"host-1\"}]", "[]");
        var disabled = await new InternalBriefGenerationCommands(
                new InternalRiskQueries(new StubInternalRiskStore(snapshot)), new StubKevStore(), store,
                new StubSettingsStore(ActiveSettings() with { IsActive = false }), disabledLlm)
            .GenerateAsync(_ => { }, CancellationToken.None);
        Assert.Equal("AI is currently disabled in settings.", disabled.Message);

        var failed = await new InternalBriefGenerationCommands(
                new InternalRiskQueries(new StubInternalRiskStore(snapshot)), new StubKevStore(), store,
                new StubSettingsStore(ActiveSettings()), new StubLlm(new LlmChatCompletionResult(false, null, "offline")))
            .GenerateAsync(_ => { }, CancellationToken.None);
        Assert.False(failed.Success);
        Assert.StartsWith("Internal asset correlation failed; no complete brief was saved.", failed.Message);
        Assert.Null(store.SavedInternalBrief);

        var incomplete = await new InternalBriefGenerationCommands(
                new InternalRiskQueries(new StubInternalRiskStore(snapshot)), new StubKevStore(), store,
                new StubSettingsStore(ActiveSettings()),
                new StubLlm(new LlmChatCompletionResult(true, "AI failed to process batch.", null)))
            .GenerateAsync(_ => { }, CancellationToken.None);
        Assert.False(incomplete.Success);
        Assert.StartsWith("Internal asset correlation failed; no complete brief was saved.", incomplete.Message);
        Assert.Null(store.SavedInternalBrief);
    }

    private static InternalRiskSnapshotEntry Snapshot(string hardware, string software)
    {
        using var hw = JsonDocument.Parse(hardware);
        using var sw = JsonDocument.Parse(software);
        return new InternalRiskSnapshotEntry(
            1, DateTime.UtcNow, 75, "HIGH", 2, 2, 1,
            hw.RootElement.Clone(), sw.RootElement.Clone(), "auto");
    }

    private static AiSmtpSettings ActiveSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 128_000,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubInternalRiskStore(InternalRiskSnapshotEntry? snapshot) : IInternalRiskStore
    {
        public Task<InternalRiskAssetInventory> GetAssetInventoryAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new InternalRiskAssetInventory([], []));
        public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) => Task.FromResult(snapshot);
        public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<InternalRiskHistoryPoint>>([]);
        public Task SaveSnapshotAsync(InternalRiskSnapshotEntry snapshot, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubKevStore : ICisaKevStore
    {
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CisaKevEntry>>(
                [new CisaKevEntry(1, "CVE-2026-1234", "Palo Alto", "PAN-OS", "Command injection", DateTime.UtcNow, null, null, null)]);
    }

    private sealed class StubDashboardStore : IOperationalDashboardStore
    {
        public string? SavedInternalBrief { get; private set; }
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new DashboardMetrics(0, 0, 0, 0));
        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DashboardRegionalHazard>>([]);
        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyThreatScoreEntry>>([]);
        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<DashboardBriefSnapshot?>(null);
        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken)
        {
            SavedInternalBrief = content;
            return Task.FromResult(true);
        }
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
            LlmProviderSettings settings, IReadOnlyList<LlmChatMessage> messages, double temperature,
            int maxTokens, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Calls.Add((messages, temperature));
            return Task.FromResult(responses[Calls.Count - 1]);
        }
    }
}
