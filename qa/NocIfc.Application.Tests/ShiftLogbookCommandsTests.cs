using NocIfc.Application.Abstractions.Logbook;
using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Logbook;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Logbook;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ShiftLogbookCommandsTests
{
    [Fact]
    public async Task NonHistoryUsersAreScopedToTheirRoleAndCurrentChicagoDay()
    {
        var store = new StubStore();
        var commands = Commands(store);

        await commands.GetEntriesAsync(User("analyst", "analyst"), "All", "2000-01-01", "2030-01-01", CancellationToken.None);

        Assert.Equal("analyst", store.RoleFilter);
        Assert.NotNull(store.StartUtc);
        Assert.NotNull(store.EndExclusiveUtc);
        Assert.Equal(TimeSpan.FromDays(1), store.EndExclusiveUtc!.Value - store.StartUtc!.Value);
    }

    [Fact]
    public async Task CreationUsesAuthenticatedIdentityAndRestrictsNonAdminRole()
    {
        var store = new StubStore { FullName = "Jane Operator" };
        var commands = Commands(store);

        await commands.CreateAsync(
            User("jane", "analyst"), "admin", "No Shift", "Completed network maintenance.", "2026-11-25", CancellationToken.None);

        Assert.Equal("Jane Operator", store.Analyst);
        Assert.Equal("analyst", store.AuthorRole);
        Assert.Equal("No Shift", store.ShiftPeriod);
        Assert.Equal("Completed network maintenance.", store.Content);
        var createdCentral = TimeZoneInfo.ConvertTimeFromUtc(
            store.CreatedAtUtc!.Value, TimeZoneInfo.FindSystemTimeZoneById("America/Chicago"));
        Assert.Equal(new DateTime(2026, 11, 25), createdCentral.Date);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.CreateAsync(
            User("jane", "analyst"), "analyst", "Night", "Invalid period", null, CancellationToken.None));
    }

    [Fact]
    public async Task DeleteRestoreRequiresOwnershipOrManageGrant()
    {
        var store = new StubStore
        {
            Entry = new ShiftLogEntry(4, "Jane Operator", "analyst", null, "Morning", "note", null, false),
            FullName = "Jane Operator",
        };
        var commands = Commands(store);

        var ownerResult = await commands.UpdateDeletedAsync(User("jane", "analyst"), 4, true, CancellationToken.None);
        var denied = await commands.UpdateDeletedAsync(User("other", "analyst"), 4, true, CancellationToken.None);
        var manager = User("manager", "manager", ["Action: Manage Shift Logs"]);
        var managerResult = await commands.UpdateDeletedAsync(manager, 4, false, CancellationToken.None);

        Assert.Equal("ok", ownerResult.Status);
        Assert.True(ownerResult.IsDeleted);
        Assert.True(denied.Forbidden);
        Assert.Equal("ok", managerResult.Status);
        Assert.False(managerResult.IsDeleted);
    }

    [Fact]
    public async Task UsesDeterministicFallbackAndAutoAppendsWhenAiIsDisabled()
    {
        var store = new StubStore
        {
            FullName = "Jane Operator",
            SummaryEntries = [new ShiftLogEntry(
                1, "Jane Operator", "analyst", null, "Morning", "Circuit ticket pending follow-up", DateTime.UtcNow, false)],
        };
        var llm = new StubLlmClient();
        var commands = new ShiftLogbookCommands(store, new StubAiSmtpSettings(AiSettings(active: false)), llm);

        var result = await commands.GenerateSummaryAsync(
            User("jane", "analyst"), "All", "Morning", "Morning Shift Handoff", true, "shift", CancellationToken.None);

        Assert.True(result.UsedFallback);
        Assert.Contains("Circuit ticket pending follow-up", result.Summary, StringComparison.Ordinal);
        Assert.Contains("Open Items and Dependencies", result.Summary, StringComparison.Ordinal);
        Assert.Equal("Morning", store.ShiftPeriod);
        Assert.Equal(result.Summary, store.Content);
        Assert.Empty(llm.Calls);
    }

    [Fact]
    public async Task UsesMapReduceForBoundedSummaryBatches()
    {
        var store = new StubStore
        {
            SummaryEntries =
            [
                new ShiftLogEntry(1, "Analyst One", "analyst", null, "Morning", "First operational event", DateTime.UtcNow, false),
                new ShiftLogEntry(2, "Analyst Two", "analyst", null, "Morning", "Second operational event", DateTime.UtcNow, false),
            ],
        };
        var llm = new StubLlmClient(
            new LlmChatCompletionResult(true, "first facts", null),
            new LlmChatCompletionResult(true, "second facts", null),
            new LlmChatCompletionResult(true, "combined digest", null),
            new LlmChatCompletionResult(true, "final operational handoff", null));
        var commands = new ShiftLogbookCommands(store,
            new StubAiSmtpSettings(AiSettings(active: true, contextWindow: 1600)), llm);

        var result = await commands.GenerateSummaryAsync(
            User("admin", "admin"), "analyst", "Morning", "Morning Shift Handoff", false, "shift", CancellationToken.None);

        Assert.False(result.UsedFallback);
        Assert.Equal("final operational handoff", result.Summary);
        Assert.Equal(4, llm.Calls.Count);
        Assert.Contains("Prepared by", llm.Calls[^1].SystemPrompt, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RejectsSkeletonNoticeAndUsesSourceOnlyFallback()
    {
        var store = new StubStore
        {
            SummaryEntries = [new ShiftLogEntry(
                1, "Analyst", "analyst", null, "Morning", "Opened circuit ticket 123", DateTime.UtcNow, false)],
        };
        var llm = new StubLlmClient(
            new LlmChatCompletionResult(true, "Mapped facts", null),
            new LlmChatCompletionResult(true, "This skeleton report must not be circulated as a complete risk assessment.", null));
        var commands = new ShiftLogbookCommands(store,
            new StubAiSmtpSettings(AiSettings(active: true)), llm);

        var result = await commands.GenerateSummaryAsync(
            User("admin", "admin"), "All", "Morning", "Morning Shift Handoff", false, "shift", CancellationToken.None);

        Assert.True(result.UsedFallback);
        Assert.Contains("No facts were inferred", result.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("skeleton report", result.Summary, StringComparison.OrdinalIgnoreCase);
    }

    private static AiSmtpSettings AiSettings(bool active, int? contextWindow = null) => new(
        "https://llm.example.test", "openai_compatible", true, "test-model", active, contextWindow,
        "smtp", false, null, null, null, null, null, false, false, "", "", false, false, false);

    private static ShiftLogbookCommands Commands(StubStore store) =>
        new(store, new StubAiSmtpSettings(AiSettings(active: false)), new StubLlmClient());

    private static AuthenticatedUser User(string username, string role, IReadOnlyList<string>? actions = null) =>
        new(username == "other" ? 2 : 1, username, role, ["Shift Logbook"], actions ?? [], []);

    private sealed class StubStore : IShiftLogbookStore
    {
        public string? RoleFilter { get; private set; }
        public DateTime? StartUtc { get; private set; }
        public DateTime? EndExclusiveUtc { get; private set; }
        public string? FullName { get; init; }
        public string? Analyst { get; private set; }
        public string? AuthorRole { get; private set; }
        public string? ShiftPeriod { get; private set; }
        public string? Content { get; private set; }
        public DateTime? CreatedAtUtc { get; private set; }
        public ShiftLogEntry? Entry { get; set; }
        public IReadOnlyList<ShiftLogEntry> SummaryEntries { get; init; } = [];

        public Task<IReadOnlyList<ShiftLogEntry>> GetEntriesAsync(
            string? roleFilter,
            DateTime? startUtc,
            DateTime? endExclusiveUtc,
            CancellationToken cancellationToken)
        {
            RoleFilter = roleFilter;
            StartUtc = startUtc;
            EndExclusiveUtc = endExclusiveUtc;
            return Task.FromResult<IReadOnlyList<ShiftLogEntry>>([]);
        }

        public Task<IReadOnlyList<ShiftLogEntry>> GetSummaryEntriesAsync(
            string? roleFilter,
            string? shiftPeriod,
            bool excludeGeneratedSummaries,
            DateTime startUtc,
            DateTime endExclusiveUtc,
            int limit,
            CancellationToken cancellationToken) => Task.FromResult(SummaryEntries);

        public Task<IReadOnlyList<string>> GetRoleNamesAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(["admin", "analyst", "manager"]);
        public Task<string?> GetUserFullNameAsync(int userId, CancellationToken cancellationToken) =>
            Task.FromResult(userId == 1 ? FullName : null);

        public Task<int> CreateAsync(
            string analyst,
            string authorRole,
            string shiftPeriod,
            string content,
            DateTime createdAtUtc,
            DateTime shiftDateUtc,
            CancellationToken cancellationToken)
        {
            Analyst = analyst;
            AuthorRole = authorRole;
            ShiftPeriod = shiftPeriod;
            Content = content;
            CreatedAtUtc = createdAtUtc;
            return Task.FromResult(1);
        }

        public Task<ShiftLogEntry?> GetByIdAsync(int entryId, CancellationToken cancellationToken) =>
            Task.FromResult(Entry);

        public Task<bool> SetDeletedAsync(int entryId, bool isDeleted, CancellationToken cancellationToken)
        {
            if (Entry is null) return Task.FromResult(false);
            Entry = Entry with { IsDeleted = isDeleted };
            return Task.FromResult(true);
        }
    }

    private sealed class StubAiSmtpSettings(AiSmtpSettings? settings) : IAiSmtpSettingsStore
    {
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(settings);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) => Task.FromResult("test-key");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubLlmClient(params LlmChatCompletionResult[] responses) : ILlmChatCompletionClient
    {
        private readonly Queue<LlmChatCompletionResult> _responses = new(responses);
        public List<LlmCall> Calls { get; } = [];

        public Task<LlmChatCompletionResult> CompleteAsync(
            LlmProviderSettings settings,
            IReadOnlyList<LlmChatMessage> messages,
            double temperature,
            int maxTokens,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Calls.Add(new LlmCall(messages[0].Content, temperature, maxTokens, timeout));
            return Task.FromResult(_responses.Count > 0
                ? _responses.Dequeue()
                : new LlmChatCompletionResult(false, null, "No test completion configured."));
        }
    }

    private sealed record LlmCall(string SystemPrompt, double Temperature, int MaxTokens, TimeSpan Timeout);
}
