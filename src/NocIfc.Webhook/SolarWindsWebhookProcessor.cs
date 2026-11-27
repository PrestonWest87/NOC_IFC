using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Features.AIOps;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Webhook;

public sealed class SolarWindsWebhookProcessor(
    SolarWindsWebhookQueue queue,
    IServiceScopeFactory scopes,
    ILogger<SolarWindsWebhookProcessor> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var message in queue.Reader.ReadAllAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<SolarWindsWebhookCommands>()
                    .ExecuteAsync(message.Body, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "SolarWinds webhook persistence failed.");
            }
            finally
            {
                queue.CompleteOne();
            }
        }
    }
}

public sealed class SolarWindsWebhookStatusWorker(
    SolarWindsWebhookQueue queue,
    IRestoreMaintenanceControl restore,
    SqliteReadinessProbe readiness,
    WebhookReadinessState readinessState,
    ILogger<SolarWindsWebhookStatusWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nextProbe = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTimeOffset.UtcNow;
            if (restore.MaintenanceRequested)
            {
                readinessState.SetReady(false);
            }
            else if (now >= nextProbe && readinessState.TryBeginProbe(restore))
            {
                PublishStatus();
                try
                {
                    readinessState.SetReady(await readiness.IsReadyAsync(stoppingToken));
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    readinessState.SetReady(false);
                    logger.LogWarning(exception, "Webhook gateway is waiting for SQLite readiness.");
                }
                finally
                {
                    readinessState.EndProbe();
                    nextProbe = DateTimeOffset.UtcNow.AddSeconds(5);
                }
            }
            PublishStatus();
            await Task.Delay(TimeSpan.FromMilliseconds(500), stoppingToken);
        }
    }

    private void PublishStatus()
    {
        var active = queue.Pending + readinessState.ActiveProbes;
        var state = restore.MaintenanceRequested
            ? active > 0 ? "draining" : "paused"
            : "running";
        try
        {
            restore.PublishProcessStatus("webhook", state, active,
                queue.Pending > 0 ? ["solarwinds_webhook"] : []);
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Unable to publish SolarWinds webhook status.");
        }
    }
}

public sealed class WebhookReadinessState
{
    private int _ready;
    private int _activeProbes;

    public bool IsReady => Volatile.Read(ref _ready) != 0;
    public int ActiveProbes => Volatile.Read(ref _activeProbes);

    public void SetReady(bool ready) => Volatile.Write(ref _ready, ready ? 1 : 0);

    public bool TryBeginProbe(IRestoreMaintenanceControl restore)
    {
        if (restore.MaintenanceRequested) return false;
        Interlocked.Increment(ref _activeProbes);
        if (!restore.MaintenanceRequested) return true;
        EndProbe();
        return false;
    }

    public void EndProbe() => Interlocked.Decrement(ref _activeProbes);
}
