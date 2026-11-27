using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SchedulerSettingsCommandsTests
{
    [Fact]
    public async Task ReturnsRegistryDefaultsAndValidatesPersistedOverrides()
    {
        var store = new StubStore();
        var commands = new SchedulerSettingsCommands(store);
        var snapshot = await commands.GetAsync(CancellationToken.None);

        Assert.Equal(21, snapshot.Jobs.Count);
        Assert.Equal(4, snapshot.Revision);
        Assert.Equal(3, snapshot.AppliedRevision);
        Assert.Equal(1, snapshot.Jobs.Single(job => job.Key == "tiered_alert_escalation").Schedule.EveryValue);

        var result = await commands.SaveAsync(
            "rss_fetch",
            new SchedulerScheduleUpdate(null, 10, null, null, null, null, false),
            "operator",
            8,
            CancellationToken.None);

        Assert.Equal(5, result.Revision);
        Assert.Equal("rss_fetch", result.JobKey);
        Assert.Equal("minutes", result.Schedule.Unit);
        Assert.Equal(10, result.Schedule.EveryValue);
        Assert.False(result.Schedule.Enabled);
        Assert.Equal("operator", store.UpdatedBy);
    }

    [Fact]
    public async Task RejectsUnsafeJobsAndInvalidScheduleValues()
    {
        var commands = new SchedulerSettingsCommands(new StubStore());
        var disabledEscalation = new SchedulerScheduleUpdate(null, null, null, null, null, null, false);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "tiered_alert_escalation", disabledEscalation, "admin", 1, CancellationToken.None));

        var invalidInterval = new SchedulerScheduleUpdate(null, 31, null, null, null, null, null);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "rss_fetch", invalidInterval, "admin", 1, CancellationToken.None));

        var wrongUnit = new SchedulerScheduleUpdate(null, 5, "hours", null, null, null, null);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "rss_fetch", wrongUnit, "admin", 1, CancellationToken.None));

        var wrongTimezone = new SchedulerScheduleUpdate(null, null, null, "03:00", null, "UTC", null);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "global_brief", wrongTimezone, "admin", 1, CancellationToken.None));

        var wrongWeekday = new SchedulerScheduleUpdate(null, null, null, "00:00", "funday", null, null);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "database_backup", wrongWeekday, "admin", 1, CancellationToken.None));

        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            "not_a_job", new SchedulerScheduleUpdate(null, null, null, null, null, null, null),
            "admin", 1, CancellationToken.None));
    }

    private sealed class StubStore : ISchedulerSettingsStore
    {
        public string? UpdatedBy { get; private set; }

        public Task<SchedulerSettingsState> GetAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new SchedulerSettingsState(4, 3, new Dictionary<string, SchedulerStoredJob>()));

        public Task<int> SaveAsync(
            string jobKey,
            SchedulerSchedule schedule,
            string updatedBy,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            UpdatedBy = updatedBy;
            return Task.FromResult(5);
        }

        public Task MarkAppliedAsync(int revision, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
