using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Reporting;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CustomReportCommandsTests
{
    [Fact]
    public async Task GeneratesSourceGroundedReportFromSelectedArticlesWithForcedReduction()
    {
        var article = Article(7, new string('x', 2001));
        var articleStore = new StubArticleStore { Articles = [article] };
        var huntingStore = new StubHuntingStore();
        var settingsStore = new StubSettingsStore(ActiveSettings() with { LlmProvider = "ollama_native" });
        var llm = new StubLlm("Evidence digest", "## Executive Assessment\nOperational risk is elevated.");
        var command = new CustomReportCommands(
            new ThreatArticleQueries(articleStore),
            new ThreatHuntingQueries(huntingStore),
            settingsStore,
            llm);
        var progress = new List<CustomReportProgress>();

        var result = await command.GenerateAsync(
            new CustomReportGenerationInput(" APT29 ", 7, [7, 7], "Assess operational significance.", "Analyst One"),
            progress.Add,
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Contains("# 📋 NOC Custom Intel Report", result.Content);
        Assert.Contains("**Target:** APT29", result.Content);
        Assert.Contains("**Analyst:** Analyst One", result.Content);
        Assert.Matches(@"\*\*Date:\*\* .* (CST|CDT)", result.Content);
        Assert.Equal(new[] { 7 }, articleStore.RequestedIds);
        Assert.False(huntingStore.SearchCalled);
        Assert.Equal("ollama_native", settingsStore.RequestedProvider);
        Assert.Equal(2, llm.Calls.Count);
        Assert.Contains("User objective: Assess operational significance.", llm.Calls[0].Messages[0].Content);
        Assert.Contains("SOURCE: Test Source | TITLE: Source title 7", llm.Calls[0].Messages[1].Content);
        Assert.Contains(new string('x', 2000) + "...", llm.Calls[0].Messages[1].Content);
        Assert.Contains("Evidence digest", llm.Calls[1].Messages[1].Content);
        Assert.Equal(0.1, llm.Calls[0].Temperature);
        Assert.Equal(0.2, llm.Calls[1].Temperature);
        Assert.All(llm.Calls, call => Assert.Equal(TimeSpan.FromSeconds(300), call.Timeout));
        Assert.Equal("complete", progress[^1].Stage);
        Assert.Equal(100, progress[^1].Percent);
    }

    [Fact]
    public async Task SearchesWhenNoArticleIdsAreSelectedAndReturnsCompatibleGenerationErrors()
    {
        var article = Article(3, "Article evidence");
        var huntingStore = new StubHuntingStore { Articles = [article] };
        var llm = new StubLlm("Evidence digest", "Finished assessment");
        var command = new CustomReportCommands(
            new ThreatArticleQueries(new StubArticleStore()),
            new ThreatHuntingQueries(huntingStore),
            new StubSettingsStore(ActiveSettings()),
            llm);

        var searched = await command.GenerateAsync(
            new CustomReportGenerationInput("ransomware", 14, [], "", "Unknown"),
            _ => { },
            CancellationToken.None);

        Assert.True(searched.Success);
        Assert.True(huntingStore.SearchCalled);
        Assert.Equal(14, huntingStore.SearchDaysBack);

        var empty = await new CustomReportCommands(
                new ThreatArticleQueries(new StubArticleStore()),
                new ThreatHuntingQueries(new StubHuntingStore()),
                new StubSettingsStore(ActiveSettings()),
                llm)
            .GenerateAsync(
                new CustomReportGenerationInput("ransomware", 7, [], "", "Unknown"),
                _ => { },
                CancellationToken.None);
        Assert.False(empty.Success);
        Assert.Equal("No articles found for the given target.", empty.Message);

        var disabled = await new CustomReportCommands(
                new ThreatArticleQueries(new StubArticleStore { Articles = [article] }),
                new ThreatHuntingQueries(new StubHuntingStore()),
                new StubSettingsStore(ActiveSettings() with { IsActive = false }),
                llm)
            .GenerateAsync(
                new CustomReportGenerationInput("", 7, [3], "", "Unknown"),
                _ => { },
                CancellationToken.None);
        Assert.False(disabled.Success);
        Assert.Equal("Report generation failed or AI is disabled.", disabled.Message);
    }

    [Fact]
    public async Task ReturnsGenerationErrorWhenEveryEvidenceMapCallFails()
    {
        var llm = new StubLlm(new string?[] { null });
        var command = new CustomReportCommands(
            new ThreatArticleQueries(new StubArticleStore { Articles = [Article(9, "Evidence")] }),
            new ThreatHuntingQueries(new StubHuntingStore()),
            new StubSettingsStore(ActiveSettings()),
            llm);
        var progress = new List<CustomReportProgress>();

        var result = await command.GenerateAsync(
            new CustomReportGenerationInput("", 7, [9], "", "Unknown"),
            progress.Add,
            CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("Report generation failed or AI is disabled.", result.Message);
        Assert.Single(llm.Calls);
        Assert.Equal("error", progress[^1].Stage);
    }

    private static ThreatArticle Article(int id, string content) => new(
        id, $"Source title {id}", null, "Summary", DateTime.UtcNow, "Test Source", 90, "Cyber",
        [], false, null, content, null, false, DateTime.UtcNow, null, null, null, null);

    private static AiSmtpSettings ActiveSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 8192,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubArticleStore : IThreatArticleStore
    {
        public IReadOnlyList<ThreatArticle> Articles { get; init; } = [];
        public IReadOnlyList<int> RequestedIds { get; private set; } = [];
        public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<ThreatArticlePage> GetPageAsync(
            string category, string categoryFilter, int page, int pageSize, string? searchTerm, int minimumScore,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ThreatArticlePage([], 0, 1, 1));
        public Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken) =>
            Task.FromResult<ThreatArticleDetail?>(null);
        public Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(
            IReadOnlyList<int> articleIds, CancellationToken cancellationToken)
        {
            RequestedIds = articleIds;
            return Task.FromResult<IReadOnlyList<ThreatArticle>>(
                Articles.Where(article => articleIds.Contains(article.Id)).ToArray());
        }
        public Task TogglePinAsync(int articleId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubHuntingStore : IThreatHuntingStore
    {
        public IReadOnlyList<ThreatArticle> Articles { get; init; } = [];
        public bool SearchCalled { get; private set; }
        public int SearchDaysBack { get; private set; }
        public Task<IReadOnlyList<ExtractedIocEntry>> GetRecentIocsAsync(
            DateTime detectedAfterUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ExtractedIocEntry>>([]);
        public Task<IReadOnlyList<ThreatArticle>> SearchArticlesAsync(
            DateTime publishedAfterUtc, IReadOnlyList<string> terms, int limit, CancellationToken cancellationToken)
        {
            SearchCalled = true;
            SearchDaysBack = (int)Math.Round((DateTime.UtcNow - publishedAfterUtc).TotalDays);
            return Task.FromResult(Articles);
        }
        public Task<PagedElasticEvents> GetElasticEventsAsync(
            DateTime createdAfterUtc, int page, int pageSize, int hoursBack, CancellationToken cancellationToken) =>
            Task.FromResult(new PagedElasticEvents([], 0, page, pageSize, hoursBack));
        public Task<int> AddElasticEventsAsync(IReadOnlyList<ElasticEventEntry> events, CancellationToken cancellationToken) =>
            Task.FromResult(0);
    }

    private sealed class StubSettingsStore(AiSmtpSettings? settings) : IAiSmtpSettingsStore
    {
        public string? RequestedProvider { get; private set; }
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken)
        {
            RequestedProvider = provider;
            return Task.FromResult("saved-key");
        }
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubLlm(params string?[] responses) : ILlmChatCompletionClient
    {
        public List<(IReadOnlyList<LlmChatMessage> Messages, double Temperature, TimeSpan Timeout)> Calls { get; } = [];
        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add((messages, temperature, timeout));
            var content = responses[Calls.Count - 1];
            return Task.FromResult(content is null
                ? new LlmChatCompletionResult(false, null, "offline")
                : new LlmChatCompletionResult(true, content, null));
        }
    }
}
