using System.Collections.Concurrent;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NocIfc.Application.Abstractions.BackupRestore;

namespace NocIfc.Api.Services;

public sealed class RestoreCoordinator(
    IBackupManager backups,
    IRestoreMaintenanceControl control,
    ILogger<RestoreCoordinator> logger) : IHostedService
{
    private static readonly TimeSpan QuiesceTimeout = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, Lazy<Task>> running = new(StringComparer.Ordinal);

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (control.GetActiveRestore() is { } active) Launch(active);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public string StartRestore(string stageId, string requestedBy)
    {
        _ = backups.ValidateStagedBackup(stageId);
        var request = control.BeginRestore(stageId, requestedBy);
        Launch(request);
        return request.RestoreId;
    }

    private void Launch(RestoreControlRequest request)
    {
        var task = running.GetOrAdd(request.RestoreId,
            _ => new Lazy<Task>(() => Task.Run(() => RunRestoreAsync(request)), LazyThreadSafetyMode.ExecutionAndPublication));
        _ = task.Value;
    }

    private async Task RunRestoreAsync(RestoreControlRequest request)
    {
        try
        {
            control.UpdateRestore(request.RestoreId, "quiescing", "Pausing API and worker writers.", 5);
            await WaitForWritersAsync(request.RestoreId, CancellationToken.None);
            control.UpdateRestore(request.RestoreId, "restoring", "Validating and installing the encrypted database snapshot.", 20);
            var result = backups.RestoreStagedBackup(request.StageId, maintenanceConfirmed: true);
            control.UpdateRestore(request.RestoreId, "reloading", "Reloading data from the restored SQLite database.", 90);
            control.FinishRestore(request.RestoreId, "complete",
                "Restore completed. Restored sessions and account links were invalidated; sign in again.", result);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "C# UI-initiated restore failed restore_id={RestoreId}", request.RestoreId);
            try
            {
                control.FinishRestore(request.RestoreId, "error",
                    string.IsNullOrWhiteSpace(exception.Message)
                        ? "Restore failed; the existing database was preserved or rolled back."
                        : exception.Message[..Math.Min(exception.Message.Length, 500)]);
            }
            catch (Exception finishException)
            {
                logger.LogError(finishException, "Unable to release restore maintenance mode restore_id={RestoreId}",
                    request.RestoreId);
            }
        }
        finally
        {
            running.TryRemove(request.RestoreId, out _);
        }
    }

    private async Task WaitForWritersAsync(string restoreId, CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow + QuiesceTimeout;
        string? lastMessage = null;
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (control.GetActiveRestore()?.RestoreId != restoreId)
            {
                throw new InvalidOperationException("Restore maintenance mode was cleared before writers quiesced.");
            }
            var worker = control.GetProcessStatus("worker", restoreId);
            var pending = new List<string>();
            if (control.ActiveApiRequests > 0 || control.ActiveApiBackgroundWriters > 0)
            {
                pending.Add("API requests/background tasks");
            }
            if (worker is null || worker.State != "paused" || worker.Active > 0) pending.Add("scheduler worker");
            if (pending.Count == 0) return;
            var message = $"Waiting for {string.Join(" and ", pending)} to finish active writes.";
            if (!string.Equals(message, lastMessage, StringComparison.Ordinal))
            {
                control.UpdateRestore(restoreId, "quiescing", message, 5);
                lastMessage = message;
            }
            await Task.Delay(TimeSpan.FromMilliseconds(500), cancellationToken);
        }
        throw new TimeoutException(
            "The API and worker did not become idle within the maintenance window. No restore was installed; retry after active work completes.");
    }
}
