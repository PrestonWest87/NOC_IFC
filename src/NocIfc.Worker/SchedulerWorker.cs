using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Worker;

public sealed class SchedulerWorker(
    IServiceScopeFactory scopes,
    SqliteReadinessProbe readiness,
    IRestoreMaintenanceControl restore,
    ILogger<SchedulerWorker> logger) : BackgroundService
{
    private static readonly TimeSpan SettingsPollInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan LoopInterval = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(2);
    private static readonly string[][] StartupGroups =
    [
        ["tiered_alert_escalation", "maintenance_expiry", "rss_fetch", "nws_alerts"],
        ["cisa_kev", "regional_hazards", "cloud_outages"],
        ["telemetry_sync", "elastic_sync", "crime_fetch", "internal_risk"],
        ["unified_brief", "global_brief", "internal_brief"],
    ];
    private readonly ConcurrentDictionary<string, Task> _running = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _unsupportedJobsLogged = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ScheduledJob> _jobs = new(StringComparer.Ordinal);
    private int _settingsReads;
    private int _revision = -1;
    private bool _initialSettingsLoaded;
    private bool _restorePaused;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var nextSettingsPoll = DateTimeOffset.MinValue;
        var nextHeartbeat = DateTimeOffset.MinValue;
        PublishStatus("starting");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                if (restore.MaintenanceRequested)
                {
                    _restorePaused = true;
                    PublishStatus("paused");
                    await Task.Delay(LoopInterval, stoppingToken);
                    continue;
                }
                try
                {
                    if (await readiness.IsReadyAsync(stoppingToken)) break;
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exception)
                {
                    logger.LogWarning(exception, "Worker is waiting for SQLite readiness.");
                }
                PublishStatus("starting");
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }

            if (stoppingToken.IsCancellationRequested) return;
            var unhandled = SchedulerSettingsCommands.Registry
                .Where(job => !ScheduledJobExecutor.IsSupported(job.Key)).Select(job => job.Key).ToArray();
            if (unhandled.Length > 0)
            {
                throw new InvalidOperationException($"C# Worker has no handler for scheduler jobs: {string.Join(", ", unhandled)}.");
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                var now = DateTimeOffset.UtcNow;
                if (restore.MaintenanceRequested)
                {
                    _restorePaused = true;
                    PublishStatus();
                    await Task.Delay(LoopInterval, stoppingToken);
                    continue;
                }

                if (_restorePaused)
                {
                    _restorePaused = false;
                    _revision = -1;
                    nextSettingsPoll = DateTimeOffset.MinValue;
                    ResetPendingStartupRuns(now);
                }

                if (now >= nextSettingsPoll)
                {
                    nextSettingsPoll = now + SettingsPollInterval;
                    try
                    {
                        await ReloadSettingsAsync(stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception exception)
                    {
                        logger.LogError(exception, "Unable to load persisted C# scheduler settings.");
                    }
                }

                if (!restore.MaintenanceRequested) StartDueJobs(DateTimeOffset.UtcNow, stoppingToken);
                if (DateTimeOffset.UtcNow >= nextHeartbeat)
                {
                    PublishStatus();
                    nextHeartbeat = DateTimeOffset.UtcNow + HeartbeatInterval;
                }
                await Task.Delay(LoopInterval, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            await Task.WhenAll(_running.Values);
        }
    }

    private async Task ReloadSettingsAsync(CancellationToken cancellationToken)
    {
        if (restore.MaintenanceRequested) return;
        Interlocked.Increment(ref _settingsReads);
        PublishStatus();
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<ISchedulerSettingsStore>();
            var snapshot = await store.GetAsync(cancellationToken);
            if (snapshot.Revision != _revision)
            {
                ApplySnapshot(snapshot, _initialSettingsLoaded, DateTimeOffset.UtcNow);
                _revision = snapshot.Revision;
                _initialSettingsLoaded = true;
            }
            if (snapshot.AppliedRevision < snapshot.Revision)
            {
                await store.MarkAppliedAsync(snapshot.Revision, cancellationToken);
            }
        }
        finally
        {
            Interlocked.Decrement(ref _settingsReads);
            PublishStatus();
        }
    }

    private void ApplySnapshot(SchedulerSettingsState snapshot, bool startupComplete, DateTimeOffset now)
    {
        var startupOffsets = StartupGroups
            .SelectMany((group, index) => group.Select(key => (key, index)))
            .GroupBy(item => item.key, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First().index, StringComparer.Ordinal);
        foreach (var definition in SchedulerSettingsCommands.Registry)
        {
            snapshot.Jobs.TryGetValue(definition.Key, out var stored);
            var schedule = stored?.Schedule ?? definition.DefaultSchedule;
            if (!definition.CanDisable && !schedule.Enabled) schedule = schedule with { Enabled = true };
            if (_jobs.TryGetValue(definition.Key, out var previous) && previous.Schedule == schedule)
            {
                previous.Definition = definition;
                continue;
            }

            DateTimeOffset? nextRun = schedule.Enabled ? SchedulerScheduleClock.NextRunUtc(schedule, now) : null;
            DateTimeOffset? startupAt = null;
            var startupGroup = 0;
            if (!startupComplete && definition.StartupRun && schedule.Enabled)
            {
                if (startupOffsets.TryGetValue(definition.Key, out startupGroup))
                {
                    startupAt = now.AddSeconds(startupGroup * 30);
                }
                else
                {
                    startupAt = now;
                }
            }
            _jobs[definition.Key] = new ScheduledJob(definition, schedule, nextRun, startupAt, startupGroup);
        }
    }

    private void ResetPendingStartupRuns(DateTimeOffset now)
    {
        foreach (var job in _jobs.Values.Where(job => job.StartupAt is not null))
        {
            job.StartupAt = now.AddSeconds(job.StartupGroup * 30);
        }
    }

    private void StartDueJobs(DateTimeOffset now, CancellationToken stoppingToken)
    {
        foreach (var job in _jobs.Values)
        {
            if (!job.Schedule.Enabled) continue;
            if (job.StartupAt is { } startupAt && startupAt <= now)
            {
                if (StartJob(job.Definition.Key, stoppingToken))
                {
                    job.StartupAt = null;
                    job.NextRunAt = SchedulerScheduleClock.NextRunUtc(job.Schedule, now);
                }
                continue;
            }
            if (job.NextRunAt is not { } nextRun || nextRun > now) continue;
            var started = StartJob(job.Definition.Key, stoppingToken);
            if (started || _running.ContainsKey(job.Definition.Key))
            {
                job.NextRunAt = SchedulerScheduleClock.NextRunUtc(job.Schedule, now);
            }
        }
    }

    private bool StartJob(string key, CancellationToken stoppingToken)
    {
        if (!ScheduledJobExecutor.IsSupported(key))
        {
            if (_unsupportedJobsLogged.TryAdd(key, 0))
            {
                logger.LogWarning("Scheduled job {JobKey} is not implemented in the C# Worker yet.", key);
            }
            return true;
        }
        if (restore.MaintenanceRequested || _running.ContainsKey(key)) return false;
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_running.TryAdd(key, completion.Task)) return false;
        PublishStatus();
        _ = RunJobAsync(key, completion, stoppingToken);
        return true;
    }

    private async Task RunJobAsync(string key, TaskCompletionSource<bool> completion, CancellationToken stoppingToken)
    {
        try
        {
            await Task.Yield();
            await using var scope = scopes.CreateAsyncScope();
            await ScheduledJobExecutor.ExecuteAsync(key, scope.ServiceProvider, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Scheduled job {JobKey} failed.", key);
        }
        finally
        {
            _running.TryRemove(key, out _);
            PublishStatus();
            completion.TrySetResult(true);
        }
    }

    private void PublishStatus(string? requestedState = null)
    {
        var jobs = _running.Keys.OrderBy(key => key, StringComparer.Ordinal).ToArray();
        var active = jobs.Length + Volatile.Read(ref _settingsReads);
        var state = requestedState ?? (restore.MaintenanceRequested
            ? active > 0 ? "draining" : "paused"
            : "running");
        try
        {
            restore.PublishWorkerStatus(state, active, jobs);
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "Unable to publish scheduler worker status.");
        }
    }

    private sealed class ScheduledJob(
        SchedulerJobDefinition definition,
        SchedulerSchedule schedule,
        DateTimeOffset? nextRunAt,
        DateTimeOffset? startupAt,
        int startupGroup)
    {
        public SchedulerJobDefinition Definition { get; set; } = definition;
        public SchedulerSchedule Schedule { get; } = schedule;
        public DateTimeOffset? NextRunAt { get; set; } = nextRunAt;
        public DateTimeOffset? StartupAt { get; set; } = startupAt;
        public int StartupGroup { get; } = startupGroup;
    }
}
