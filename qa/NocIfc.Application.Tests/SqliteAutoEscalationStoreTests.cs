using Microsoft.Data.Sqlite;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAutoEscalationStoreTests
{
    [Fact]
    public async Task EnforcesSameNodeCooldownAndRecordsTicketAndPageDelivery()
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
                CREATE TABLE solarwinds_alerts (
                    id INTEGER PRIMARY KEY, node_name TEXT, mapped_location TEXT, is_dispatched BOOLEAN,
                    dispatched_at DATETIME, is_ticketed BOOLEAN, received_at DATETIME,
                    status TEXT, onpage_sent_at DATETIME
                );
                CREATE TABLE monitored_locations (name TEXT, last_escalation_ticket DATETIME);
                INSERT INTO solarwinds_alerts VALUES
                    (1, 'node-a', 'Central NOC', 1, '2026-05-02 11:00:00', 0, '2026-05-02 10:30:00', 'Down', NULL),
                    (2, 'node-a', 'Central NOC', 0, NULL, 0, '2026-05-02 11:30:00', 'Down', NULL),
                    (3, 'node-b', 'Central NOC', 0, NULL, 0, '2026-05-02 11:30:00', 'Resolved', NULL);
                INSERT INTO monitored_locations VALUES ('Central NOC', NULL);
                """;
            await setup.ExecuteNonQueryAsync();
        }
        var store = new SqliteAutoEscalationStore(connections);

        Assert.True(await store.IsNodeOnCooldownAsync(
            2, "node-a", "Central NOC", new DateTime(2026, 5, 2, 10, 0, 0), CancellationToken.None));
        Assert.False(await store.IsNodeOnCooldownAsync(
            2, "node-b", "Central NOC", new DateTime(2026, 5, 2, 10, 0, 0), CancellationToken.None));
        Assert.Equal(1, await store.MarkTicketedAsync([2], CancellationToken.None));
        Assert.Equal(2, await store.MarkPageSentAsync("Central NOC", "node-a", 2,
            new DateTime(2026, 5, 2, 12, 0, 0), CancellationToken.None));

        Assert.Equal(1, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE is_ticketed = 1")));
        Assert.Equal(2, Convert.ToInt32(Scalar(databasePath,
            "SELECT COUNT(*) FROM solarwinds_alerts WHERE node_name = 'node-a' AND onpage_sent_at IS NOT NULL")));
        Assert.NotNull(Scalar(databasePath,
            "SELECT last_escalation_ticket FROM monitored_locations WHERE name = 'Central NOC'"));
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
        public string Path { get; } = Directory.CreateTempSubdirectory("nocifc-escalation-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
