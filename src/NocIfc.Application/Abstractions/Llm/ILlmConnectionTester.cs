namespace NocIfc.Application.Abstractions.Llm;

public sealed record LlmConnectionTestSettings(
    string Provider,
    string Endpoint,
    string ApiKey,
    string ModelName);

public sealed record LlmConnectionTestResult(bool Success, string Message);

public interface ILlmConnectionTester
{
    Task<LlmConnectionTestResult> TestAsync(
        LlmConnectionTestSettings settings,
        CancellationToken cancellationToken);
}
