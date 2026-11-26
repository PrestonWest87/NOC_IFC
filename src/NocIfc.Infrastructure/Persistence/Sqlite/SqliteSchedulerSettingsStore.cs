using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteSchedulerSettingsStore(SqliteConnectionFactory connections) : ISchedulerSettingsStore
{
    public async Task<SchedulerSettingsState> GetAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var revision = 0;
        var appliedRevision = 0;
        await using (var config = connection.CreateCommand())
        {
            config.CommandText = "SELECT scheduler_revision, scheduler_applied_revision FROM system_config ORDER BY id LIMIT 1";
            await using var reader = await config.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                revision = reader.GetInt32(0);
                appliedRevision = reader.GetInt32(1);
            }
        }

        var jobs = new Dictionary<string, SchedulerStoredJob>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT job_key, schedule_type, every_value, unit, run_at, weekday,
                       timezone, enabled, updated_by, updated_at
                FROM scheduler_job_config
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                jobs[reader.GetString(0)] = new SchedulerStoredJob(
                    new SchedulerSchedule(
                        reader.GetString(1),
                        reader.GetBoolean(7),
                        reader.IsDBNull(2) ? null : reader.GetInt32(2),
                        ReadString(reader, 3),
                        ReadString(reader, 4),
                        ReadString(reader, 5),
                        ReadString(reader, 6)),
                    ReadString(reader, 8),
                    ReadIsoDateTime(reader, 9));
            }
        }
        return new SchedulerSettingsState(revision, appliedRevision, jobs);
    }

    public async Task<int> SaveAsync(
        string jobKey,
        SchedulerSchedule schedule,
        string updatedBy,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using (var exists = connection.CreateCommand())
        {
            exists.CommandText = "SELECT 1 FROM system_config ORDER BY id LIMIT 1";
            if (await exists.ExecuteScalarAsync(cancellationToken) is null)
            {
                await SqliteApplicationSettingsStore.InsertDefaultsAsync(
                    connection,
                    new GlobalApplicationSettingsUpdate(null, null, null, null, null, null, null),
                    cancellationToken);
            }
        }

        using var transaction = connection.BeginTransaction();
        long configId;
        await using (var config = connection.CreateCommand())
        {
            config.Transaction = transaction;
            config.CommandText = "SELECT id FROM system_config ORDER BY id LIMIT 1";
            var value = await config.ExecuteScalarAsync(cancellationToken);
            if (value is null or DBNull)
            {
                throw new InvalidOperationException("Unable to initialize scheduler settings.");
            }
            configId = Convert.ToInt64(value, CultureInfo.InvariantCulture);
        }

        int revision;
        await using (var updateRevision = connection.CreateCommand())
        {
            updateRevision.Transaction = transaction;
            updateRevision.CommandText = "UPDATE system_config SET scheduler_revision = COALESCE(scheduler_revision, 0) + 1 WHERE id = $id";
            updateRevision.Parameters.AddWithValue("$id", configId);
            await updateRevision.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var readRevision = connection.CreateCommand())
        {
            readRevision.Transaction = transaction;
            readRevision.CommandText = "SELECT scheduler_revision FROM system_config WHERE id = $id";
            readRevision.Parameters.AddWithValue("$id", configId);
            revision = Convert.ToInt32(await readRevision.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        }

        var updatedAt = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
        await using (var upsert = connection.CreateCommand())
        {
            upsert.Transaction = transaction;
            upsert.CommandText = """
                INSERT INTO scheduler_job_config
                    (job_key, schedule_type, every_value, unit, run_at, weekday, timezone,
                     enabled, updated_by, updated_at)
                VALUES
                    ($job_key, $schedule_type, $every_value, $unit, $run_at, $weekday,
                     $timezone, $enabled, $updated_by, $updated_at)
                ON CONFLICT(job_key) DO UPDATE SET
                    schedule_type = excluded.schedule_type,
                    every_value = excluded.every_value,
                    unit = excluded.unit,
                    run_at = excluded.run_at,
                    weekday = excluded.weekday,
                    timezone = excluded.timezone,
                    enabled = excluded.enabled,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """;
            upsert.Parameters.AddWithValue("$job_key", jobKey);
            upsert.Parameters.AddWithValue("$schedule_type", schedule.ScheduleType);
            upsert.Parameters.AddWithValue("$every_value", (object?)schedule.EveryValue ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$unit", (object?)schedule.Unit ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$run_at", (object?)schedule.RunAt ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$weekday", (object?)schedule.Weekday ?? DBNull.Value);
            upsert.Parameters.AddWithValue("$timezone", schedule.Timezone ?? "America/Chicago");
            upsert.Parameters.AddWithValue("$enabled", schedule.Enabled);
            upsert.Parameters.AddWithValue("$updated_by", updatedBy[..Math.Min(updatedBy.Length, 128)]);
            upsert.Parameters.AddWithValue("$updated_at", updatedAt);
            await upsert.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var audit = connection.CreateCommand())
        {
            audit.Transaction = transaction;
            audit.CommandText = """
                INSERT INTO account_audit_events
                    (actor_user_id, subject_user_id, event_type, event_detail, created_at)
                VALUES ($actor_id, NULL, 'scheduler_setting_changed', $detail, $created_at)
                """;
            audit.Parameters.AddWithValue("$actor_id", actorUserId);
            audit.Parameters.AddWithValue("$detail", JsonSerializer.Serialize(new
            {
                job_key = jobKey,
                schedule = ScheduleDetails(schedule),
                revision,
            }));
            audit.Parameters.AddWithValue("$created_at", updatedAt);
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return revision;
    }

    private static Dictionary<string, object> ScheduleDetails(SchedulerSchedule schedule)
    {
        var details = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["schedule_type"] = schedule.ScheduleType,
            ["enabled"] = schedule.Enabled,
        };
        if (schedule.EveryValue is { } everyValue) details["every_value"] = everyValue;
        if (schedule.Unit is not null) details["unit"] = schedule.Unit;
        if (schedule.RunAt is not null) details["run_at"] = schedule.RunAt;
        if (schedule.Weekday is not null) details["weekday"] = schedule.Weekday;
        if (schedule.Timezone is not null) details["timezone"] = schedule.Timezone;
        return details;
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string? ReadIsoDateTime(SqliteDataReader reader, int ordinal)
    {
        var value = ReadString(reader, ordinal);
        return value is not null
            && DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed)
                ? parsed.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture)
                : value;
    }
}
