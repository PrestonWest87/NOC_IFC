using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SchedulerScheduleClockTests
{
    [Fact]
    public void IntervalSchedulesUseUtcDurations()
    {
        var now = DateTimeOffset.Parse("2026-05-01T12:00:00Z");
        var next = SchedulerScheduleClock.NextRunUtc(
            new SchedulerSchedule("interval", true, 2, "hours"), now);

        Assert.Equal(DateTimeOffset.Parse("2026-05-01T14:00:00Z"), next);
    }

    [Fact]
    public void DailyScheduleMovesForwardAcrossTheSpringDstGap()
    {
        var now = DateTimeOffset.Parse("2026-03-08T07:00:00Z");
        var next = SchedulerScheduleClock.NextRunUtc(
            new SchedulerSchedule("daily", true, RunAt: "02:30", Timezone: "America/Chicago"), now);

        Assert.Equal(DateTimeOffset.Parse("2026-03-08T08:00:00Z"), next);
    }

    [Fact]
    public void WeeklyScheduleChoosesTheEarlierFallDstOverlap()
    {
        var now = DateTimeOffset.Parse("2026-11-01T05:00:00Z");
        var next = SchedulerScheduleClock.NextRunUtc(
            new SchedulerSchedule("weekly", true, RunAt: "01:30", Weekday: "sunday", Timezone: "America/Chicago"), now);

        Assert.Equal(DateTimeOffset.Parse("2026-11-01T06:30:00Z"), next);
    }
}
