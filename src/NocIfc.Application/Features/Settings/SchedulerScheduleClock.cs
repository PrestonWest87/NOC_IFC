using System.Globalization;

namespace NocIfc.Application.Features.Settings;

public static class SchedulerScheduleClock
{
    private static readonly TimeZoneInfo CentralTimeZone =
        TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    public static DateTimeOffset NextRunUtc(SchedulerSchedule schedule, DateTimeOffset nowUtc)
    {
        if (schedule.ScheduleType == "interval")
        {
            var interval = schedule.Unit switch
            {
                "minutes" => TimeSpan.FromMinutes(schedule.EveryValue ?? 0),
                "hours" => TimeSpan.FromHours(schedule.EveryValue ?? 0),
                _ => throw new ArgumentException("Unsupported scheduler interval unit.", nameof(schedule)),
            };
            if (interval <= TimeSpan.Zero) throw new ArgumentException("Scheduler interval must be positive.", nameof(schedule));
            return nowUtc.ToUniversalTime() + interval;
        }

        if (schedule.Timezone != "America/Chicago"
            || schedule.ScheduleType is not ("daily" or "weekly")
            || !TimeOnly.TryParseExact(schedule.RunAt, "HH:mm", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var runAt))
        {
            throw new ArgumentException("Scheduler wall-time settings are invalid.", nameof(schedule));
        }
        var weeklyDay = schedule.ScheduleType == "weekly"
            ? Enum.TryParse<DayOfWeek>(schedule.Weekday, true, out var day)
                ? day
                : throw new ArgumentException("Scheduler weekday is invalid.", nameof(schedule))
            : (DayOfWeek?)null;
        var localToday = DateOnly.FromDateTime(TimeZoneInfo.ConvertTime(nowUtc, CentralTimeZone).DateTime);

        for (var dayOffset = 0; dayOffset <= 7; dayOffset++)
        {
            var date = localToday.AddDays(dayOffset);
            if (weeklyDay is { } selectedDay && date.DayOfWeek != selectedDay) continue;
            var local = DateTime.SpecifyKind(date.ToDateTime(runAt), DateTimeKind.Unspecified);
            for (var adjustment = 0; CentralTimeZone.IsInvalidTime(local) && adjustment < 180; adjustment++)
            {
                local = local.AddMinutes(1);
            }
            if (CentralTimeZone.IsInvalidTime(local)) continue;
            var offset = CentralTimeZone.IsAmbiguousTime(local)
                ? CentralTimeZone.GetAmbiguousTimeOffsets(local).Max()
                : CentralTimeZone.GetUtcOffset(local);
            var occurrenceUtc = new DateTimeOffset(local, offset).ToUniversalTime();
            if (occurrenceUtc > nowUtc.ToUniversalTime()) return occurrenceUtc;
        }

        throw new InvalidOperationException("Unable to calculate the next scheduler run time.");
    }
}
