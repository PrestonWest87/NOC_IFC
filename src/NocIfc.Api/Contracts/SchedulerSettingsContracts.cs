using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Contracts;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class SchedulerUpdateRequest
{
    [JsonPropertyName("schedule")]
    public SchedulerScheduleUpdateRequest? Schedule { get; init; }

    public SchedulerScheduleUpdate ToUpdate() =>
        Schedule?.ToUpdate() ?? throw new ArgumentException("Provide a schedule object.");
}

public sealed class SchedulerScheduleUpdateRequest
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Values { get; init; } = new(StringComparer.Ordinal);

    public SchedulerScheduleUpdate ToUpdate()
    {
        var allowed = new HashSet<string>(
            ["schedule_type", "every_value", "unit", "run_at", "weekday", "timezone", "enabled"],
            StringComparer.Ordinal);
        var unknown = Values.Keys.FirstOrDefault(key => !allowed.Contains(key));
        if (unknown is not null)
        {
            throw new ArgumentException($"Unsupported schedule setting: {unknown}");
        }

        return new SchedulerScheduleUpdate(
            ReadString("schedule_type"),
            ReadInt("every_value"),
            ReadString("unit"),
            ReadString("run_at"),
            ReadString("weekday"),
            ReadString("timezone"),
            ReadBool("enabled"));
    }

    private string? ReadString(string key)
    {
        if (!Values.TryGetValue(key, out var value))
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.String)
        {
            throw new ArgumentException($"{key} must be text.");
        }
        return value.GetString();
    }

    private int? ReadInt(string key)
    {
        if (!Values.TryGetValue(key, out var value))
        {
            return null;
        }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number))
        {
            throw new ArgumentException($"{key} must be a whole number.");
        }
        return number;
    }

    private bool? ReadBool(string key)
    {
        if (!Values.TryGetValue(key, out var value))
        {
            return null;
        }
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new ArgumentException($"{key} must be a boolean.");
        }
        return value.GetBoolean();
    }
}

public sealed record SchedulerScheduleResponse(
    [property: JsonPropertyName("schedule_type")] string ScheduleType,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("every_value"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? EveryValue,
    [property: JsonPropertyName("unit"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Unit,
    [property: JsonPropertyName("run_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RunAt,
    [property: JsonPropertyName("weekday"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Weekday,
    [property: JsonPropertyName("timezone"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Timezone)
{
    public static SchedulerScheduleResponse From(SchedulerSchedule schedule) => new(
        schedule.ScheduleType,
        schedule.Enabled,
        schedule.EveryValue,
        schedule.Unit,
        schedule.RunAt,
        schedule.Weekday,
        schedule.Timezone);
}

public sealed record SchedulerJobResponse(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("schedule")] SchedulerScheduleResponse Schedule,
    [property: JsonPropertyName("min_value")] int? MinValue,
    [property: JsonPropertyName("max_value")] int? MaxValue,
    [property: JsonPropertyName("can_disable")] bool CanDisable,
    [property: JsonPropertyName("startup_run")] bool StartupRun,
    [property: JsonPropertyName("updated_by")] string? UpdatedBy,
    [property: JsonPropertyName("updated_at")] string? UpdatedAt)
{
    public static SchedulerJobResponse From(SchedulerJobSettings job) => new(
        job.Key,
        job.Label,
        job.Description,
        SchedulerScheduleResponse.From(job.Schedule),
        job.MinValue,
        job.MaxValue,
        job.CanDisable,
        job.StartupRun,
        job.UpdatedBy,
        job.UpdatedAt);
}

public sealed record SchedulerSettingsResponse(
    [property: JsonPropertyName("revision")] int Revision,
    [property: JsonPropertyName("applied_revision")] int AppliedRevision,
    [property: JsonPropertyName("jobs")] IReadOnlyList<SchedulerJobResponse> Jobs)
{
    public static SchedulerSettingsResponse From(SchedulerSettingsSnapshot settings) => new(
        settings.Revision,
        settings.AppliedRevision,
        settings.Jobs.Select(SchedulerJobResponse.From).ToArray());
}

public sealed record SchedulerUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("revision")] int Revision,
    [property: JsonPropertyName("job_key")] string JobKey,
    [property: JsonPropertyName("schedule")] SchedulerScheduleResponse Schedule)
{
    public static SchedulerUpdateResponse From(SchedulerSettingsUpdateResult result) => new(
        "saved",
        result.Revision,
        result.JobKey,
        SchedulerScheduleResponse.From(result.Schedule));
}
