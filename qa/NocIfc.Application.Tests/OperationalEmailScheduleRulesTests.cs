using NocIfc.Application.Features.OperationalEmail;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class OperationalEmailScheduleRulesTests
{
    [Fact]
    public void OneTimeScheduleRequiresFutureOffsetTimestampAndNormalizesUtc()
    {
        var now = new DateTimeOffset(2026, 11, 27, 18, 0, 0, TimeSpan.Zero);
        var result = OperationalEmailScheduleRules.Validate(
            new OperationalEmailScheduleInput("once", new DateTimeOffset(2026, 11, 28, 2, 30, 0, TimeSpan.FromHours(-6)), null, null, "America/Chicago"),
            now);

        Assert.Equal("once", result.ScheduleType);
        Assert.Equal(new DateTime(2026, 11, 28, 8, 30, 0, DateTimeKind.Utc), result.NextRunAt);
        Assert.Throws<ArgumentException>(() => OperationalEmailScheduleRules.Validate(
            new OperationalEmailScheduleInput("once", now, null, null, "America/Chicago"), now));
    }

    [Fact]
    public void RecurringScheduleUsesCentralDstWallTimeRules()
    {
        var springGap = OperationalEmailScheduleRules.Validate(
            new OperationalEmailScheduleInput("daily", null, "02:30", null, "America/Chicago"),
            new DateTimeOffset(2027, 3, 14, 6, 0, 0, TimeSpan.Zero));
        var fallOverlap = OperationalEmailScheduleRules.Validate(
            new OperationalEmailScheduleInput("weekly", null, "01:30", 6, "America/Chicago"),
            new DateTimeOffset(2027, 11, 7, 6, 45, 0, TimeSpan.Zero));

        Assert.Equal(new DateTime(2027, 3, 14, 8, 30, 0, DateTimeKind.Utc), springGap.NextRunAt);
        Assert.Equal(new DateTime(2027, 11, 14, 7, 30, 0, DateTimeKind.Utc), fallOverlap.NextRunAt);
    }
}
