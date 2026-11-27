using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using NocIfc.Application.Features.Dashboard;

namespace NocIfc.Api.Services;

public sealed class UnifiedBriefGenerationState(
    IServiceScopeFactory scopeFactory,
    ILogger<UnifiedBriefGenerationState> logger)
{
    private readonly ConcurrentDictionary<Guid, UnifiedBriefGenerationProgress> _progress = new();

    public Guid Start()
    {
        var id = Guid.NewGuid();
        _progress[id] = new UnifiedBriefGenerationProgress("starting", "Starting generation...", 0, 0, 0, null);
        _ = Task.Run(() => RunAsync(id));
        return id;
    }

    public UnifiedBriefGenerationProgress? GetProgress(Guid id) =>
        _progress.TryGetValue(id, out var progress) ? progress : null;

    private async Task RunAsync(Guid id)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var commands = scope.ServiceProvider.GetRequiredService<UnifiedBriefGenerationCommands>();
            await commands.GenerateAsync(progress => _progress[id] = progress, CancellationToken.None);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unified brief generation {GenerationId} failed.", id);
            _progress[id] = new UnifiedBriefGenerationProgress(
                "error", "Brief generation failed.", 0, 0, 0, "Brief generation failed.");
        }
    }
}
