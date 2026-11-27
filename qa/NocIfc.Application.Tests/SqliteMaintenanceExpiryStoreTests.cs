using Microsoft.Data.Sqlite;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteMaintenanceExpiryStoreTests
{
    [Fact]
    public async Task ClearsOnlyMaintenanceWindowsExpiredBeforeCentralToday()
    {
        using var workspace = new TemporaryDirectory();
        var databasePath = Path.Combine(workspace.Path, "database.sqlite");
        using (File.Create(databasePath)) { }
        var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
        await using (var connection = connections.Create())
        {
            await connection.OpenAsync();
            await using var setup = connection.CreateCommand();
            setup.CommandText = """
                CREATE TABLE monitored_locations (
                    name TEXT, under_maintenance BOOLEAN, maintenance_etr DATETIME,
                    maintenance_reason TEXT, status_modified_by TEXT, status_modified_at DATETIME
                );
                INSERT INTO monitored_locations VALUES
                    ('Expired', 1, '2026-05-01 00:00:00', 'old', NULL, NULL),
                    ('Today', 1, '2026-05-02 00:00:00', 'active', NULL, NULL),
                    ('Not in maintenance', 0, '2026-05-01 00:00:00', 'old', NULL, NULL);
                """;
            await setup.ExecuteNonQueryAsync();
        }
        var store = new SqliteMaintenanceExpiryStore(connections);

        var cleared = await store.ClearExpiredAsync(
            new DateOnly(2026, 5, 2), new DateTime(2026, 5, 2, 5, 1, 0, DateTimeKind.Utc),
            CancellationToken.None);

        Assert.Equal(new[] { "Expired" }, cleared);
        Assert.Null(Scalar(databasePath, "SELECT maintenance_etr FROM monitored_locations WHERE name = 'Expired'"));
        Assert.Null(Scalar(databasePath, "SELECT maintenance_reason FROM monitored_locations WHERE name = 'Expired'"));
        Assert.Equal("System (ETR Expired)", Scalar(databasePath,
            "SELECT status_modified_by FROM monitored_locations WHERE name = 'Expired'"));
        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT under_maintenance FROM monitored_locations WHERE name = 'Today'")));
        Assert.Equal(0, Convert.ToInt32(Scalar(databasePath,
            "SELECT under_maintenance FROM monitored_locations WHERE name = 'Not in maintenance'")));
    }

    private static object? Scalar(string databasePath, string query)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = query;
        var result = command.ExecuteScalar();
        return result is DBNull ? null : result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-maintenance-expiry-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
