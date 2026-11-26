using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteSchedulerSettingsStoreTests
{
    [Fact]
    public async Task SavesSchedulesWithRevisionAndAuditAtomicallyAndUpsertsExistingJobs()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-scheduler-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE system_config (
                        id INTEGER PRIMARY KEY, scheduler_revision INTEGER NOT NULL,
                        scheduler_applied_revision INTEGER NOT NULL
                    );
                    INSERT INTO system_config VALUES (1, 4, 3);
                    CREATE TABLE scheduler_job_config (
                        id INTEGER PRIMARY KEY, job_key TEXT NOT NULL UNIQUE,
                        schedule_type TEXT NOT NULL, every_value INTEGER, unit TEXT,
                        run_at TEXT, weekday TEXT, timezone TEXT NOT NULL,
                        enabled INTEGER NOT NULL, updated_by TEXT, updated_at DATETIME NOT NULL
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT NOT NULL, event_detail TEXT NOT NULL, created_at DATETIME NOT NULL
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteSchedulerSettingsStore(connections);
            var initial = await store.GetAsync(CancellationToken.None);
            Assert.Equal(4, initial.Revision);
            Assert.Equal(3, initial.AppliedRevision);
            Assert.Empty(initial.Jobs);

            var firstRevision = await store.SaveAsync(
                "rss_fetch",
                new SchedulerSchedule("interval", true, 10, "minutes"),
                "operator",
                9,
                CancellationToken.None);
            var secondRevision = await store.SaveAsync(
                "rss_fetch",
                new SchedulerSchedule("interval", false, 15, "minutes"),
                "admin",
                1,
                CancellationToken.None);

            Assert.Equal(5, firstRevision);
            Assert.Equal(6, secondRevision);
            var updated = await store.GetAsync(CancellationToken.None);
            Assert.Equal(3, updated.AppliedRevision);
            var savedJob = Assert.Single(updated.Jobs);
            Assert.Equal(15, savedJob.Value.Schedule.EveryValue);
            Assert.False(savedJob.Value.Schedule.Enabled);
            Assert.Equal("America/Chicago", savedJob.Value.Schedule.Timezone);
            Assert.Equal("admin", savedJob.Value.UpdatedBy);
            Assert.Contains("T", savedJob.Value.UpdatedAt, StringComparison.Ordinal);

            await using var auditConnection = connections.Create();
            await auditConnection.OpenAsync();
            await using var audit = auditConnection.CreateCommand();
            audit.CommandText = "SELECT actor_user_id, event_type, event_detail FROM account_audit_events ORDER BY id";
            await using var reader = await audit.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.Equal(9, reader.GetInt32(0));
            Assert.Equal("scheduler_setting_changed", reader.GetString(1));
            Assert.Contains("rss_fetch", reader.GetString(2), StringComparison.Ordinal);
            Assert.True(await reader.ReadAsync());
            Assert.Equal(1, reader.GetInt32(0));
            Assert.Contains("revision", reader.GetString(2), StringComparison.Ordinal);
            Assert.False(await reader.ReadAsync());
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
