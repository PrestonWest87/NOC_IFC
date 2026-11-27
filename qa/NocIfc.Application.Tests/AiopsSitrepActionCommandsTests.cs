using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AiopsSitrepActionCommandsTests
{
    [Fact]
    public async Task RefreshBriefingSavesOnlySuccessfulSummary()
    {
        var store = new StubActionStore
        {
            RollingInputs = new AiopsRollingBriefInputs(["router outage"], [], []),
        };
        var llm = new StubLlmClient(
            new LlmChatCompletionResult(true, "Two paragraph summary.", null),
            new LlmChatCompletionResult(false, null, "endpoint unavailable"));
        var commands = Commands(store, llm, ActiveAiSettings());

        var success = await commands.RefreshBriefingAsync(CancellationToken.None);
        var failure = await commands.RefreshBriefingAsync(CancellationToken.None);

        Assert.True(success.Success);
        Assert.Equal("Two paragraph summary.", success.Content);
        Assert.Equal("Two paragraph summary.", store.SavedSummary);
        Assert.False(failure.Success);
        Assert.Contains("[WARN]", failure.Content);
        Assert.Equal("Two paragraph summary.", store.SavedSummary);
        Assert.Equal(2, llm.Calls.Count);
        Assert.Equal(0.2, llm.Calls[0].Temperature);
        Assert.Equal(4096, llm.Calls[0].MaxTokens);
        Assert.Contains("router outage", llm.Calls[0].Messages[1].Content);
    }

    [Fact]
    public async Task ScoringRationaleCombinesMapAndFinalCompletion()
    {
        var llm = new StubLlmClient(
            new LlmChatCompletionResult(true, "Router exploit reported by CISA.", null),
            new LlmChatCompletionResult(true, "Executive rationale.", null));
        var commands = Commands(new StubActionStore(), llm, ActiveAiSettings());
        var intel = new AiopsScoringRationaleInput(
            "ORANGE",
            [new AiopsScoringRationaleArticle("CISA", "Cyber", "Router exploit", "A vulnerability was reported.")],
            [],
            []);

        var result = await commands.GenerateScoringRationaleAsync(intel, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("Executive rationale.", result.Content);
        Assert.Equal(2, llm.Calls.Count);
        Assert.Contains("Extract the core threats", llm.Calls[0].Messages[0].Content);
        Assert.Contains("current system threat level is **ORANGE**", llm.Calls[1].Messages[0].Content);
        Assert.Contains("CISA", llm.Calls[1].Messages[1].Content);
    }

    [Fact]
    public async Task SecurityAuditUsesConfiguredTechStackAndCveMatches()
    {
        var llm = new StubLlmClient(
            new LlmChatCompletionResult(true, "MATCH: CVE-2026-1234 affects Vendor Alpha.", null),
            new LlmChatCompletionResult(true, "Patch Vendor Alpha immediately.", null));
        var commands = Commands(
            new StubActionStore
            {
                Cves = [new CisaKevEntry(1, "CVE-2026-1234", "Vendor Alpha", "Router", "Remote code execution", null, null, null, null)],
            },
            llm,
            ActiveAiSettings(),
            new GlobalApplicationSettings("", "Vendor Alpha / SCADA", "", false, "", 5, 5));

        var report = await commands.GenerateSecurityAuditAsync(CancellationToken.None);

        Assert.StartsWith("MATCH DETECTED:\n\nPatch Vendor Alpha", report);
        Assert.Contains("Vendor Alpha / SCADA", llm.Calls[0].Messages[0].Content);
        Assert.Contains("CVE-2026-1234", llm.Calls[0].Messages[1].Content);
        Assert.Equal(2, llm.Calls.Count);
    }

    private static AiopsSitrepActionCommands Commands(
        StubActionStore store,
        StubLlmClient llm,
        AiSmtpSettings? aiSettings = null,
        GlobalApplicationSettings? applicationSettings = null) => new(
        store,
        new StubAiSmtpSettingsStore(aiSettings ?? ActiveAiSettings()),
        new StubApplicationSettingsStore(applicationSettings ?? new GlobalApplicationSettings("", "", "", false, "", 5, 5)),
        store,
        new SiteTypeQueries(new StubSiteTypeDirectory()),
        llm);

    private static AiSmtpSettings ActiveAiSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 8192,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubActionStore : IAiopsSitrepActionStore, ICisaKevStore
    {
        public AiopsRollingBriefInputs RollingInputs { get; init; } = new([], [], []);
        public IReadOnlyList<CisaKevEntry> Cves { get; init; } = [];
        public string? SavedSummary { get; private set; }

        public Task<AiopsRollingBriefInputs> GetRollingBriefInputsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(RollingInputs);
        public Task SaveRollingSummaryAsync(string summary, DateTime savedAtUtc, CancellationToken cancellationToken)
        {
            SavedSummary = summary;
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CisaKevEntry>>(Cves.Take(limit).ToArray());
    }

    private sealed class StubLlmClient(params LlmChatCompletionResult[] results) : ILlmChatCompletionClient
    {
        public List<LlmCall> Calls { get; } = [];

        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add(new LlmCall(settings, messages, temperature, maxTokens, timeout));
            return Task.FromResult(results[Calls.Count - 1]);
        }
    }

    private sealed record LlmCall(
        LlmProviderSettings Settings,
        IReadOnlyList<LlmChatMessage> Messages,
        double Temperature,
        int MaxTokens,
        TimeSpan Timeout);

    private sealed class StubAiSmtpSettingsStore(AiSmtpSettings? settings) : IAiSmtpSettingsStore
    {
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) => Task.FromResult("saved-key");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubApplicationSettingsStore(GlobalApplicationSettings settings) : IApplicationSettingsStore
    {
        public Task<GlobalApplicationSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<GlobalApplicationSettings?>(settings);
        public Task<bool> ActiveEmailProfileIsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(false);
        public Task SaveAsync(GlobalApplicationSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubSiteTypeDirectory : ISiteTypeDirectory
    {
        public Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(["NOC", "SOC"]);
    }
}
