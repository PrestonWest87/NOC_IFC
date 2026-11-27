using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using NocIfc.Application.Features.Dashboard;

namespace NocIfc.Api.Services;

public sealed class DashboardBriefGenerationState(
    IServiceScopeFactory scopeFactory,
    ILogger<DashboardBriefGenerationState> logger)
{
    private readonly ConcurrentDictionary<Guid, BriefGenerationProgress> _progress = new();

    public Guid StartUnified() => Start(BriefKind.Unified);

    public Guid StartGlobal() => Start(BriefKind.Global);

    public BriefGenerationProgress? GetProgress(Guid id) =>
        _progress.TryGetValue(id, out var progress) ? progress : null;

    private Guid Start(BriefKind kind)
    {
        var id = Guid.NewGuid();
        _progress[id] = new BriefGenerationProgress("starting", "Starting generation...", 0, 0, 0, null);
        _ = Task.Run(() => RunAsync(id, kind));
        return id;
    }

    private async Task RunAsync(Guid id, BriefKind kind)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var commands = scope.ServiceProvider;
            var result = kind switch
            {
                BriefKind.Unified => await commands.GetRequiredService<UnifiedBriefGenerationCommands>()
                    .GenerateAsync(progress => _progress[id] = progress, CancellationToken.None),
                BriefKind.Global => await commands.GetRequiredService<GlobalBriefGenerationCommands>()
                    .GenerateAsync(progress => _progress[id] = progress, CancellationToken.None),
                _ => throw new InvalidOperationException("Unsupported dashboard brief kind."),
            };
            if (!result.Success)
            {
                _progress[id] = new BriefGenerationProgress(
                    "error", result.Message ?? "Brief generation failed.", 0, 0, 0,
                    result.Message ?? "Brief generation failed.");
            }
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Dashboard brief generation {GenerationId} ({BriefKind}) failed.", id, kind);
            _progress[id] = new BriefGenerationProgress(
                "error", "Brief generation failed.", 0, 0, 0, "Brief generation failed.");
        }
    }

    private enum BriefKind
    {
        Unified,
        Global,
    }
}
