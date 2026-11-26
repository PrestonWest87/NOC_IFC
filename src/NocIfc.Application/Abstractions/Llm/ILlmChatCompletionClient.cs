namespace NocIfc.Application.Abstractions.Llm;

public sealed record LlmChatMessage(string Role, string Content);

public sealed record LlmChatCompletionResult(bool Success, string? Content, string? Error);

public interface ILlmChatCompletionClient
{
    Task<LlmChatCompletionResult> CompleteAsync(
        LlmProviderSettings settings,
        IReadOnlyList<LlmChatMessage> messages,
        double temperature,
        int maxTokens,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}
