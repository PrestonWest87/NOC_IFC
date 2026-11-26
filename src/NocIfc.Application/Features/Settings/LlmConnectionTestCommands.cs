using NocIfc.Application.Abstractions.Llm;
using NocIfc.Application.Abstractions.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed record LlmConnectionTestInput(
    string? Provider,
    string? Endpoint,
    string? ApiKey,
    string? ModelName);

public sealed class LlmConnectionTestCommands(
    IAiSmtpSettingsStore settings,
    ILlmConnectionTester tester)
{
    private static readonly HashSet<string> Providers =
    ["openai_compatible", "ollama_openai", "ollama_native", "vllm"];

    public async Task<LlmConnectionTestResult> TestAsync(
        LlmConnectionTestInput input,
        CancellationToken cancellationToken)
    {
        var provider = string.IsNullOrWhiteSpace(input.Provider)
            ? "openai_compatible"
            : input.Provider.Trim().ToLowerInvariant();
        if (!Providers.Contains(provider))
        {
            return new LlmConnectionTestResult(false, $"Unsupported LLM provider: {provider}.");
        }
        var endpoint = (input.Endpoint ?? "").Trim().TrimEnd('/');
        var modelName = (input.ModelName ?? "").Trim();
        if (endpoint.Length == 0)
        {
            return new LlmConnectionTestResult(false, "Endpoint URL is required.");
        }
        if (modelName.Length == 0)
        {
            return new LlmConnectionTestResult(false, "Model name is required.");
        }
        if (endpoint.Length > 2048 || modelName.Length > 256 || input.ApiKey?.Length > 4096)
        {
            return new LlmConnectionTestResult(false, "LLM connection test settings exceed their maximum length.");
        }
        var apiKey = (input.ApiKey ?? "").Trim();
        if (apiKey.Length == 0)
        {
            apiKey = await settings.GetSavedLlmApiKeyForProviderAsync(provider, cancellationToken);
        }
        return await tester.TestAsync(
            new LlmConnectionTestSettings(provider, endpoint, apiKey, modelName),
            cancellationToken);
    }
}
