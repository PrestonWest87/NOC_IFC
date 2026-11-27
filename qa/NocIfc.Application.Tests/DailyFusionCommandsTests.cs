using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Reporting;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Reporting;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class DailyFusionCommandsTests
{
    [Fact]
    public async Task GeneratesAndArchivesThePreviousCentralDayReport()
    {
        var store = new StubStore
        {
            Inputs = new DailyFusionInputs(
                [Article("Router outage")],
                [new CisaKevEntry(1, "CVE-2026-0001", "Vendor", "Router", "Vulnerability", null, null, null, null)],
                [new DailyFusionHazard("Severe", "Tornado Warning", "Central")],
                [new DailyFusionCloudOutage("Azure", "Compute", "Regional issue")]),
        };
        var llm = new StubLlmChatCompletionClient(
            "Cyber digest", "KEV digest", "Hazard digest", "Cloud digest", "Final report");
        var command = new DailyFusionCommands(store, new StubAiSmtpSettingsStore(ActiveAiSettings()), llm);

        var result = await command.GenerateAsync(CancellationToken.None);

        var central = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, TimeZoneInfo.FindSystemTimeZoneById("America/Chicago"));
        var expectedDate = DateOnly.FromDateTime(central.DateTime).AddDays(-1);
        Assert.True(result.Success);
        Assert.Equal(expectedDate.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture), result.Date);
        Assert.Equal("Final report", result.Content);
        Assert.Equal(result.Content, store.SavedContent);
        Assert.Equal(expectedDate.ToDateTime(TimeOnly.MinValue), store.SavedReportDate);
        Assert.Equal(5, llm.Calls.Count);
        Assert.Contains("Router outage", llm.Calls[0].Messages[1].Content);
        Assert.Contains("CVE-2026-0001", llm.Calls[1].Messages[1].Content);
        Assert.Equal(0.2, llm.Calls[^1].Temperature);
    }

    [Fact]
    public async Task UsesDeterministicFallbackWhenFinalSummaryFails()
    {
        var store = new StubStore { Inputs = new DailyFusionInputs([], [], [], []) };
        var llm = new StubLlmChatCompletionClient((string?)null);
        var command = new DailyFusionCommands(store, new StubAiSmtpSettingsStore(ActiveAiSettings()), llm);

        var result = await command.GenerateAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains("NOC Daily Fusion Report:", result.Content);
        Assert.Contains("No critical intelligence alerts tracked yesterday.", result.Content);
        Assert.Contains("No new KEVs added yesterday.", result.Content);
        Assert.Equal(result.Content, store.SavedContent);
    }

    [Fact]
    public async Task ReturnsDisabledAiErrorWithoutReadingOrSavingReport()
    {
        var store = new StubStore();
        var llm = new StubLlmChatCompletionClient("not used");
        var command = new DailyFusionCommands(store, new StubAiSmtpSettingsStore(ActiveAiSettings() with { IsActive = false }), llm);

        var result = await command.GenerateAsync(CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("Report generation failed or AI is disabled.", result.Message);
        Assert.Null(store.SavedContent);
        Assert.Empty(llm.Calls);
    }

    private static ThreatArticle Article(string title) => new(
        1, title, null, "Summary", DateTime.UtcNow, "OSINT", 90, "Cyber: Malware & Threats",
        [], false, null, null, null, false, DateTime.UtcNow, null, null, null, null);

    private static AiSmtpSettings ActiveAiSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 8192,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubStore : IDailyBriefingStore
    {
        public DailyFusionInputs Inputs { get; init; } = new([], [], [], []);
        public string? SavedContent { get; private set; }
        public DateTime? SavedReportDate { get; private set; }
        public Task<IReadOnlyList<DailyBriefingEntry>> GetAllAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyBriefingEntry>>([]);
        public Task<DailyFusionInputs> GetGenerationInputsAsync(DateTime startUtc, DateTime endUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(Inputs);
        public Task SaveAsync(DateTime reportDateLocal, string content, DateTime createdAtUtc, CancellationToken cancellationToken)
        {
            SavedReportDate = reportDateLocal;
            SavedContent = content;
            return Task.CompletedTask;
        }
    }

    private sealed class StubAiSmtpSettingsStore(AiSmtpSettings? settings) : IAiSmtpSettingsStore
    {
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) => Task.FromResult("saved-key");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubLlmChatCompletionClient(params string?[] responses) : ILlmChatCompletionClient
    {
        public List<(IReadOnlyList<LlmChatMessage> Messages, double Temperature, int MaxTokens)> Calls { get; } = [];

        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add((messages, temperature, maxTokens));
            var response = responses[Calls.Count - 1];
            return Task.FromResult(response is null
                ? new LlmChatCompletionResult(false, null, "offline")
                : new LlmChatCompletionResult(true, response, null));
        }
    }
}
