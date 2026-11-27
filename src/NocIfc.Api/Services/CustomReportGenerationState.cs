using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Features.Reporting;

namespace NocIfc.Api.Services;

public sealed class CustomReportGenerationState(
    IServiceScopeFactory scopeFactory,
    IRestoreMaintenanceControl restoreControl,
    ILogger<CustomReportGenerationState> logger)
{
    private readonly ConcurrentDictionary<Guid, GenerationState> _generations = new();

    public Guid Start(CustomReportGenerationInput input)
    {
        var id = Guid.NewGuid();
        _generations[id] = new GenerationState(
            new CustomReportProgress("starting", "Initializing report generation...", 0), null);
        if (!restoreControl.TryBeginApiBackgroundWriter())
        {
            _generations[id] = new GenerationState(
                new CustomReportProgress("error", "A database restore is in progress.", 0),
                new CustomReportGenerationResult(false, null, "A database restore is in progress."));
            return id;
        }
        _ = Task.Run(() => RunAsync(id, input));
        return id;
    }

    public CustomReportProgress? GetProgress(Guid id) =>
        _generations.TryGetValue(id, out var state) ? state.Progress : null;

    public bool TryTakeResult(Guid id, out CustomReportGenerationResult? result)
    {
        result = null;
        if (!_generations.TryGetValue(id, out var state) || state.Result is null
            || !_generations.TryRemove(id, out _))
        {
            return false;
        }
        result = state.Result;
        return true;
    }

    private async Task RunAsync(Guid id, CustomReportGenerationInput input)
    {
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var commands = scope.ServiceProvider.GetRequiredService<CustomReportCommands>();
            var result = await commands.GenerateAsync(
                input,
                progress => UpdateProgress(id, progress),
                CancellationToken.None);
            _generations.AddOrUpdate(id,
                _ => new GenerationState(new CustomReportProgress("error", "Generation state expired.", 0), result),
                (_, state) => state with { Result = result });
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Custom report generation {GenerationId} failed.", id);
            _generations.AddOrUpdate(id,
                _ => new GenerationState(new CustomReportProgress("error", "Report generation failed.", 0),
                    new CustomReportGenerationResult(false, null, "Report generation failed.")),
                (_, state) => state with
                {
                    Progress = new CustomReportProgress("error", "Report generation failed.", 0),
                    Result = new CustomReportGenerationResult(false, null, "Report generation failed."),
                });
        }
        finally
        {
            restoreControl.EndApiBackgroundWriter();
        }
    }

    private void UpdateProgress(Guid id, CustomReportProgress progress) =>
        _generations.AddOrUpdate(id,
            _ => new GenerationState(progress, null),
            (_, state) => state with { Progress = progress });

    private sealed record GenerationState(CustomReportProgress Progress, CustomReportGenerationResult? Result);
}
