using System.Globalization;
using NocIfc.Application.Abstractions.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed record SchedulerSchedule(
    string ScheduleType,
    bool Enabled,
    int? EveryValue = null,
    string? Unit = null,
    string? RunAt = null,
    string? Weekday = null,
    string? Timezone = null);

public sealed record SchedulerScheduleUpdate(
    string? ScheduleType,
    int? EveryValue,
    string? Unit,
    string? RunAt,
    string? Weekday,
    string? Timezone,
    bool? Enabled);

public sealed record SchedulerJobDefinition(
    string Key,
    string Label,
    string Description,
    SchedulerSchedule DefaultSchedule,
    int? MinValue,
    int? MaxValue,
    bool CanDisable,
    bool StartupRun);

public sealed record SchedulerStoredJob(SchedulerSchedule Schedule, string? UpdatedBy, string? UpdatedAt);

public sealed record SchedulerSettingsState(
    int Revision,
    int AppliedRevision,
    IReadOnlyDictionary<string, SchedulerStoredJob> Jobs);

public sealed record SchedulerJobSettings(
    string Key,
    string Label,
    string Description,
    SchedulerSchedule Schedule,
    int? MinValue,
    int? MaxValue,
    bool CanDisable,
    bool StartupRun,
    string? UpdatedBy,
    string? UpdatedAt);

public sealed record SchedulerSettingsSnapshot(
    int Revision,
    int AppliedRevision,
    IReadOnlyList<SchedulerJobSettings> Jobs);

public sealed record SchedulerSettingsUpdateResult(int Revision, string JobKey, SchedulerSchedule Schedule);

public sealed class SchedulerSettingsCommands(ISchedulerSettingsStore settings)
{
    private static SchedulerSchedule Interval(int every, string unit, bool enabled = true) =>
        new("interval", enabled, every, unit);

    private static SchedulerSchedule Daily(string runAt) =>
        new("daily", true, RunAt: runAt, Timezone: "America/Chicago");

    private static SchedulerSchedule Weekly(string weekday, string runAt) =>
        new("weekly", true, RunAt: runAt, Weekday: weekday, Timezone: "America/Chicago");

    public static IReadOnlyList<SchedulerJobDefinition> Registry { get; } =
    [
        new("tiered_alert_escalation", "Tiered alert escalation", "P1-P5 SLA escalation, dispatch, and on-call paging.", Interval(1, "minutes"), 1, 5, false, true),
        new("rss_fetch", "RSS feed fetch", "Fetch, score, and classify RSS articles.", Interval(5, "minutes"), 3, 30, true, true),
        new("article_enrichment", "Article enrichment", "Retrieve article full text for high-scoring items.", Interval(3, "minutes"), 1, 30, true, false),
        new("maintenance_expiry", "Maintenance expiry", "Clear site maintenance after its ETR.", Interval(5, "minutes"), 1, 30, true, true),
        new("telemetry_sync", "Telemetry sync", "Synchronize telemetry and BGP data.", Interval(6, "minutes"), 3, 60, true, true),
        new("elastic_sync", "Elastic cache sync", "Refresh high-severity Elastic events.", Interval(6, "minutes"), 5, 120, true, true),
        new("nws_alerts", "NWS active alerts", "Refresh Arkansas and the 50-mile border corridor in neighboring states.", Interval(1, "minutes"), 1, 1, false, true),
        new("regional_hazards", "Regional hazards", "Refresh SPC, USGS, and wildfire hazards.", Interval(7, "minutes"), 5, 60, true, true),
        new("cloud_outages", "Cloud status", "Refresh cloud provider outage status.", Interval(8, "minutes"), 5, 60, true, true),
        new("crime_fetch", "Crime fetch", "Refresh nearby crime incidents and alerts.", Interval(10, "minutes"), 5, 60, true, true),
        new("database_maintenance", "Database maintenance", "Run retention cleanup and SQLite maintenance.", Interval(60, "minutes"), 15, 240, true, false),
        new("internal_risk", "Internal risk calculation", "Calculate and save internal asset risk.", Interval(2, "hours"), 1, 24, true, true),
        new("rolling_summary", "Rolling shift summary", "Generate the shift handoff summary.", Interval(30, "minutes"), 15, 360, true, false),
        new("internal_brief", "Internal asset brief", "Generate the internal asset risk brief.", Interval(3, "hours"), 1, 12, true, true),
        new("unified_brief", "Unified brief", "Generate the unified cyber/physical risk brief.", Interval(6, "hours"), 2, 24, true, true),
        new("cisa_kev", "CISA KEV sync", "Refresh the Known Exploited Vulnerabilities catalog.", Interval(7, "hours"), 4, 24, true, true),
        new("global_brief", "Global threat brief", "Generate the US critical-infrastructure threat brief.", Daily("02:00"), null, null, true, true),
        new("daily_email_brief", "Daily email brief", "Email the latest unified brief to configured recipients.", Daily("07:00"), null, null, true, false),
        new("daily_fusion_report", "Daily fusion report", "Generate the previous day's fusion report.", Daily("06:00"), null, null, true, false),
        new("operational_email_queue", "Operational email queue", "Deliver persisted one-time and recurring Operational Email schedules.", Interval(1, "minutes"), 1, 1, false, false),
        new("database_backup", "Encrypted database backup", "Create a full encrypted SQLite backup and retain the latest three scheduled copies.", Weekly("sunday", "00:00"), null, null, false, false),
    ];

    private static readonly IReadOnlyDictionary<string, SchedulerJobDefinition> ByKey =
        Registry.ToDictionary(job => job.Key, StringComparer.Ordinal);

    public async Task<SchedulerSettingsSnapshot> GetAsync(CancellationToken cancellationToken)
    {
        var stored = await settings.GetAsync(cancellationToken);
        var jobs = Registry.Select(definition =>
        {
            stored.Jobs.TryGetValue(definition.Key, out var saved);
            return new SchedulerJobSettings(
                definition.Key,
                definition.Label,
                definition.Description,
                saved?.Schedule ?? definition.DefaultSchedule,
                definition.MinValue,
                definition.MaxValue,
                definition.CanDisable,
                definition.StartupRun,
                saved?.UpdatedBy,
                saved?.UpdatedAt);
        }).ToArray();
        return new SchedulerSettingsSnapshot(stored.Revision, stored.AppliedRevision, jobs);
    }

    public async Task<SchedulerSettingsUpdateResult> SaveAsync(
        string jobKey,
        SchedulerScheduleUpdate update,
        string updatedBy,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        if (!ByKey.TryGetValue(jobKey, out var definition))
        {
            throw new ArgumentException("Unknown scheduler job.");
        }

        var schedule = Validate(definition, update);
        var revision = await settings.SaveAsync(jobKey, schedule, updatedBy, actorUserId, cancellationToken);
        return new SchedulerSettingsUpdateResult(revision, jobKey, schedule);
    }

    private static SchedulerSchedule Validate(SchedulerJobDefinition definition, SchedulerScheduleUpdate update)
    {
        var defaults = definition.DefaultSchedule;
        if (update.ScheduleType is not null && update.ScheduleType != defaults.ScheduleType)
        {
            throw new ArgumentException("Schedule type cannot be changed for this job.");
        }
        var enabled = update.Enabled ?? defaults.Enabled;
        if (!definition.CanDisable && !enabled)
        {
            throw new ArgumentException("This safety-critical scheduler job cannot be disabled.");
        }

        if (defaults.ScheduleType == "interval")
        {
            var every = update.EveryValue ?? defaults.EveryValue!.Value;
            var unit = update.Unit ?? defaults.Unit!;
            if (every < definition.MinValue.GetValueOrDefault() || every > definition.MaxValue.GetValueOrDefault())
            {
                throw new ArgumentException(
                    $"Interval must be between {definition.MinValue} and {definition.MaxValue} {defaults.Unit}.");
            }
            if (unit != defaults.Unit)
            {
                throw new ArgumentException($"This job must use {defaults.Unit}.");
            }
            return new SchedulerSchedule("interval", enabled, every, unit);
        }

        var runAt = update.RunAt ?? defaults.RunAt!;
        if (!DateTime.TryParseExact(
                runAt,
                "HH:mm",
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out _))
        {
            throw new ArgumentException("Run time must use 24-hour HH:MM format.");
        }
        var timezone = update.Timezone ?? defaults.Timezone!;
        if (timezone != "America/Chicago")
        {
            throw new ArgumentException("Scheduler times must use America/Chicago.");
        }
        if (defaults.ScheduleType == "daily")
        {
            return new SchedulerSchedule("daily", enabled, RunAt: runAt, Timezone: timezone);
        }

        var weekday = (update.Weekday ?? defaults.Weekday!).ToLowerInvariant();
        if (weekday is not ("monday" or "tuesday" or "wednesday" or "thursday" or "friday" or "saturday" or "sunday"))
        {
            throw new ArgumentException("Select a valid day of the week.");
        }
        return new SchedulerSchedule("weekly", enabled, RunAt: runAt, Weekday: weekday, Timezone: timezone);
    }
}
