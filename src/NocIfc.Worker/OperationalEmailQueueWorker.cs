using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Worker;

public sealed class OperationalEmailQueueWorker(
    IServiceScopeFactory scopes,
    SqliteReadinessProbe readiness,
    IRestoreMaintenanceControl restoreControl,
    ILogger<OperationalEmailQueueWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await readiness.IsReadyAsync(stoppingToken))
        {
            throw new InvalidOperationException("The SQLite schema is not at the expected migration revision.");
        }

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (!stoppingToken.IsCancellationRequested)
        {
            if (restoreControl.MaintenanceRequested)
            {
                restoreControl.PublishWorkerStatus("paused", 0);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
                continue;
            }
            if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
            if (restoreControl.MaintenanceRequested)
            {
                restoreControl.PublishWorkerStatus("paused", 0);
                continue;
            }

            restoreControl.PublishWorkerStatus("running", 1, ["operational_email_queue"]);
            using var heartbeatCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var heartbeat = PublishHeartbeatAsync(restoreControl, heartbeatCancellation.Token);
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
            finally
            {
                heartbeatCancellation.Cancel();
                try { await heartbeat; }
                catch (OperationCanceledException) { }
                restoreControl.PublishWorkerStatus(
                    restoreControl.MaintenanceRequested ? "paused" : "running",
                    0);
            }
        }
    }

    private static async Task PublishHeartbeatAsync(
        IRestoreMaintenanceControl restoreControl,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
            restoreControl.PublishWorkerStatus(
                restoreControl.MaintenanceRequested ? "draining" : "running",
                1,
                ["operational_email_queue"]);
        }
    }
}
