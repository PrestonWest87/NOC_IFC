using System.Globalization;

namespace NocIfc.Application.Features.OperationalEmail;

public sealed record OperationalEmailScheduleInput(
    string? ScheduleType,
    DateTimeOffset? ScheduledAt,
    string? RecurrenceTime,
    int? RecurrenceWeekday,
    string? Timezone);

public sealed record OperationalEmailScheduleDefinition(
    string ScheduleType,
    string Timezone,
    DateTime? ScheduledAt,
    string? RecurrenceTime,
    int? RecurrenceWeekday,
    DateTime? NextRunAt);

public static class OperationalEmailScheduleRules
{
    public const string EmailTimezone = "America/Chicago";
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById(EmailTimezone);

    public static OperationalEmailScheduleDefinition Validate(
        OperationalEmailScheduleInput schedule,
        DateTimeOffset nowUtc)
    {
        if (schedule.RecurrenceWeekday is < 0 or > 6)
        {
            throw new ArgumentException("Choose a weekday from Monday through Sunday.");
        }
        if (schedule.ScheduleType == "once")
        {
            if (schedule.ScheduledAt is not { } scheduledAt)
            {
                throw new ArgumentException("One-time send must include a time zone.");
            }
            var scheduledUtc = scheduledAt.UtcDateTime;
            if (scheduledUtc <= nowUtc.UtcDateTime)
            {
                throw new ArgumentException("One-time send must be scheduled in the future.");
            }
            return new OperationalEmailScheduleDefinition("once", EmailTimezone, scheduledUtc, null, null, scheduledUtc);
        }
        if (schedule.ScheduleType is not ("daily" or "weekly"))
        {
            throw new ArgumentException("Choose a one-time, daily, or weekly schedule.");
        }
        if ((schedule.Timezone ?? EmailTimezone) != EmailTimezone)
        {
            throw new ArgumentException("Operational email schedules must use America/Chicago.");
        }
        if (!TimeOnly.TryParseExact(schedule.RecurrenceTime, "HH:mm", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var recurrenceTime))
        {
            throw new ArgumentException("Recurring send time must use 24-hour HH:MM format.");
        }
        if (schedule.ScheduleType == "weekly" && schedule.RecurrenceWeekday is null)
        {
            throw new ArgumentException("Choose a weekday from Monday through Sunday.");
        }
        var nextRunAt = NextRecurrence(schedule.ScheduleType, recurrenceTime, schedule.RecurrenceWeekday, nowUtc);
        return new OperationalEmailScheduleDefinition(
            schedule.ScheduleType,
            EmailTimezone,
            null,
            recurrenceTime.ToString("HH:mm", CultureInfo.InvariantCulture),
            schedule.ScheduleType == "weekly" ? schedule.RecurrenceWeekday : null,
            nextRunAt);
    }

    public static DateTime NextRecurrence(
        string scheduleType,
        TimeOnly runAt,
        int? weekday,
        DateTimeOffset afterUtc)
    {
        var nowUtc = afterUtc.UtcDateTime;
        var nowLocal = TimeZoneInfo.ConvertTime(afterUtc, CentralTimeZone);
        var candidateDate = DateOnly.FromDateTime(nowLocal.DateTime);
        if (scheduleType == "weekly")
        {
            if (weekday is < 0 or > 6)
            {
                throw new ArgumentException("Choose a weekday from Monday through Sunday.");
            }
            var mondayBasedToday = ((int)candidateDate.DayOfWeek + 6) % 7;
            candidateDate = candidateDate.AddDays(((weekday!.Value - mondayBasedToday) + 7) % 7);
        }
        else if (scheduleType != "daily")
        {
            throw new ArgumentException("Unsupported email schedule type.");
        }

        var candidate = ResolveCentralWallTime(candidateDate, runAt);
        if (candidate <= nowUtc)
        {
            candidateDate = candidateDate.AddDays(scheduleType == "weekly" ? 7 : 1);
            candidate = ResolveCentralWallTime(candidateDate, runAt);
        }
        return candidate;
    }

    private static DateTime ResolveCentralWallTime(DateOnly date, TimeOnly time)
    {
        var local = DateTime.SpecifyKind(date.ToDateTime(time), DateTimeKind.Unspecified);
        TimeSpan offset;
        if (CentralTimeZone.IsInvalidTime(local))
        {
            var previousValid = local;
            do
            {
                previousValid = previousValid.AddMinutes(-1);
            } while (CentralTimeZone.IsInvalidTime(previousValid));
            offset = CentralTimeZone.GetUtcOffset(previousValid);
        }
        else if (CentralTimeZone.IsAmbiguousTime(local))
        {
            offset = CentralTimeZone.GetAmbiguousTimeOffsets(local).Max();
        }
        else
        {
            offset = CentralTimeZone.GetUtcOffset(local);
        }
        return new DateTimeOffset(local, offset).UtcDateTime;
    }
}
