using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Worker;

public sealed class OperationalEmailQueueWorker(
    IServiceScopeFactory scopes,
    SqliteReadinessProbe readiness,
    ILogger<OperationalEmailQueueWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await readiness.IsReadyAsync(stoppingToken))
        {
            throw new InvalidOperationException("The SQLite schema is not at the expected migration revision.");
        }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var processor = scope.ServiceProvider.GetRequiredService<OperationalEmailQueueProcessor>();
                var attempted = await processor.ProcessDueAsync(DateTimeOffset.UtcNow, 25, stoppingToken);
                if (attempted > 0) logger.LogInformation("Processed {Count} queued operational emails.", attempted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Operational email queue cycle failed.");
            }
        }
    }
}
