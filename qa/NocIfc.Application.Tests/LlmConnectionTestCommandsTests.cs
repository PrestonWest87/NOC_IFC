using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class LlmConnectionTestCommandsTests
{
    [Fact]
    public async Task UsesSavedKeyOnlyForItsConfiguredProviderAndNormalizesTestInput()
    {
        var store = new StubStore();
        var tester = new StubTester();
        var commands = new LlmConnectionTestCommands(store, tester);

        var result = await commands.TestAsync(
            new LlmConnectionTestInput(" OPENAI_COMPATIBLE ", " https://8.8.8.8/v1/ ", " ", " model-x "),
            CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("openai_compatible", tester.Settings?.Provider);
        Assert.Equal("https://8.8.8.8/v1", tester.Settings?.Endpoint);
        Assert.Equal("model-x", tester.Settings?.ModelName);
        Assert.Equal("saved-openai-key", tester.Settings?.ApiKey);
        Assert.Equal("openai_compatible", store.RequestedProvider);
    }

    [Fact]
    public async Task ReturnsValidationFailuresWithoutCallingProviderTester()
    {
        var tester = new StubTester();
        var commands = new LlmConnectionTestCommands(new StubStore(), tester);

        var missingEndpoint = await commands.TestAsync(
            new LlmConnectionTestInput("openai_compatible", " ", "", "model"), CancellationToken.None);
        var missingModel = await commands.TestAsync(
            new LlmConnectionTestInput("openai_compatible", "https://8.8.8.8/v1", "", " "), CancellationToken.None);
        var unsupported = await commands.TestAsync(
            new LlmConnectionTestInput("bad-provider", "https://8.8.8.8/v1", "", "model"), CancellationToken.None);

        Assert.False(missingEndpoint.Success);
        Assert.Contains("Endpoint URL", missingEndpoint.Message, StringComparison.Ordinal);
        Assert.False(missingModel.Success);
        Assert.Contains("Model name", missingModel.Message, StringComparison.Ordinal);
        Assert.False(unsupported.Success);
        Assert.Equal(0, tester.Calls);
    }

    private sealed class StubStore : IAiSmtpSettingsStore
    {
        public string? RequestedProvider { get; private set; }
        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<AiSmtpSettings?>(null);
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken)
        {
            RequestedProvider = provider;
            return Task.FromResult(provider == "openai_compatible" ? "saved-openai-key" : "");
        }
    }

    private sealed class StubTester : ILlmConnectionTester
    {
        public LlmProviderSettings? Settings { get; private set; }
        public int Calls { get; private set; }

        public Task<LlmConnectionTestResult> TestAsync(
            LlmProviderSettings settings,
            CancellationToken cancellationToken)
        {
            Calls++;
            Settings = settings;
            return Task.FromResult(new LlmConnectionTestResult(true, "Connection successful."));
        }
    }
}
