using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class GenerateArticleBlufCommandsTests
{
    [Fact]
    public async Task GeneratesAndPersistsSourceBoundedBluf()
    {
        var article = Article(7, new string('x', 4000));
        var store = new StubArticleStore(article);
        var settings = new StubSettingsStore(ActiveSettings() with { LlmProvider = "ollama_native" });
        var llm = new StubLlm(new LlmChatCompletionResult(true, "- **Core Event:** New activity.\n", null));
        var command = new GenerateArticleBlufCommands(new ThreatArticleQueries(store), settings, llm);

        var result = await command.GenerateAsync(7, CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("- **Core Event:** New activity.", result.Bluf);
        Assert.Equal(result.Bluf, store.SavedBluf);
        Assert.Equal("ollama_native", settings.RequestedProvider);
        Assert.Contains("Title: Article 7\nContent: ", llm.Messages![1].Content);
        Assert.Equal(3000, llm.Messages[1].Content.Length - "Title: Article 7\nContent: ".Length);
        Assert.Equal(0.1, llm.Temperature);
        Assert.Equal(TimeSpan.FromSeconds(300), llm.Timeout);
    }

    [Fact]
    public async Task ReturnsNotFoundAndAiFailuresWithoutSavingThem()
    {
        var article = Article(7, "Short content");
        var missingStore = new StubArticleStore(null);
        var command = new GenerateArticleBlufCommands(
            new ThreatArticleQueries(missingStore),
            new StubSettingsStore(ActiveSettings()),
            new StubLlm(new LlmChatCompletionResult(true, "unused", null)));
        var missing = await command.GenerateAsync(999, CancellationToken.None);
        Assert.Equal("Article not found.", missing.Message);

        var disabledStore = new StubArticleStore(article);
        var disabledLlm = new StubLlm(new LlmChatCompletionResult(true, "unused", null));
        var disabled = await new GenerateArticleBlufCommands(
                new ThreatArticleQueries(disabledStore),
                new StubSettingsStore(ActiveSettings() with { IsActive = false }),
                disabledLlm)
            .GenerateAsync(7, CancellationToken.None);
        Assert.Equal("AI generation failed.", disabled.Message);
        Assert.Equal(0, disabledLlm.Calls);

        var failedStore = new StubArticleStore(article);
        var failed = await new GenerateArticleBlufCommands(
                new ThreatArticleQueries(failedStore),
                new StubSettingsStore(ActiveSettings()),
                new StubLlm(new LlmChatCompletionResult(false, null, "offline")))
            .GenerateAsync(7, CancellationToken.None);
        Assert.Equal("AI generation failed.", failed.Message);
        Assert.Null(failedStore.SavedBluf);
    }

    private static ThreatArticle Article(int id, string content) => new(
        id, $"Article {id}", null, "Summary", DateTime.UtcNow, "Feed", 80, "Cyber: Malware & Threats",
        [], false, null, content, null, false, DateTime.UtcNow, null, null, null, null);

    private static AiSmtpSettings ActiveSettings() => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", true, 8192,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private sealed class StubArticleStore(ThreatArticle? article) : IThreatArticleStore
    {
        public string? SavedBluf { get; private set; }
        public Task<IReadOnlyList<ThreatArticle>> GetPinnedAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<IReadOnlyList<ThreatArticle>> GetLiveAsync(int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<IReadOnlyList<ThreatArticle>> GetRecentForInternalRiskAsync(
            int limit, DateTime publishedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>([]);
        public Task<ThreatArticlePage> GetPageAsync(
            string category, string categoryFilter, int page, int pageSize, string? searchTerm, int minimumScore,
            CancellationToken cancellationToken) =>
            Task.FromResult(new ThreatArticlePage([], 0, 1, 1));
        public Task<ThreatArticleDetail?> GetDetailAsync(int articleId, CancellationToken cancellationToken) =>
            Task.FromResult<ThreatArticleDetail?>(null);
        public Task<IReadOnlyList<ThreatArticle>> GetByIdsAsync(
            IReadOnlyList<int> articleIds, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ThreatArticle>>(
                article is not null && articleIds.Contains(article.Id) ? [article] : []);
        public Task<bool> SaveAiBlufAsync(int articleId, string bluf, CancellationToken cancellationToken)
        {
            if (article?.Id != articleId) return Task.FromResult(false);
            SavedBluf = bluf;
            return Task.FromResult(true);
        }
        public Task TogglePinAsync(int articleId, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task BoostScoreAsync(int articleId, int amount, CancellationToken cancellationToken) => Task.CompletedTask;
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

    private sealed class StubLlm(LlmChatCompletionResult response) : ILlmChatCompletionClient
    {
        public int Calls { get; private set; }
        public IReadOnlyList<LlmChatMessage>? Messages { get; private set; }
        public LlmProviderSettings? Settings { get; private set; }
        public double Temperature { get; private set; }
        public TimeSpan Timeout { get; private set; }
        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls++;
            Settings = settings;
            Messages = messages;
            Temperature = temperature;
            Timeout = timeout;
            return Task.FromResult(response);
        }
    }
}
