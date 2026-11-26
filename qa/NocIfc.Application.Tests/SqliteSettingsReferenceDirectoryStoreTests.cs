using System.Text.Json;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteSettingsReferenceDirectoryStoreTests
{
    [Fact]
    public async Task ReplacesAllDirectoriesInDisplayOrderAndAuditsCountsWithoutValues()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-settings-directories-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE fiber_email_contacts (
                        id INTEGER PRIMARY KEY, name TEXT NOT NULL, company TEXT NOT NULL,
                        email TEXT NOT NULL, phone TEXT, sort_order INTEGER NOT NULL
                    );
                    CREATE TABLE onpage_email_contacts (
                        id INTEGER PRIMARY KEY, department TEXT NOT NULL,
                        email TEXT NOT NULL, sort_order INTEGER NOT NULL
                    );
                    CREATE TABLE network_order_circuits (
                        id INTEGER PRIMARY KEY, a_location TEXT NOT NULL, z_location TEXT NOT NULL,
                        circuit_network_order_id TEXT NOT NULL, company TEXT NOT NULL,
                        associated_circuit_network_order_ids TEXT NOT NULL, sort_order INTEGER NOT NULL
                    );
                    CREATE TABLE account_audit_events (
                        id INTEGER PRIMARY KEY, actor_user_id INTEGER, subject_user_id INTEGER,
                        event_type TEXT NOT NULL, event_detail TEXT NOT NULL, created_at DATETIME NOT NULL
                    );
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteSettingsReferenceDirectoryStore(connections);
            var fiber = await store.ReplaceFiberAsync(
            [
                new("NOC", "Carrier", "noc@carrier.example", null),
                new("Desk", "Carrier Two", "desk@carrier.example", "+1 501 555 0100"),
            ], 9, CancellationToken.None);
            var onpage = await store.ReplaceOnpageAsync(
                [new("IT Network", "it@example.test")], 9, CancellationToken.None);
            var network = await store.ReplaceNetworkOrdersAsync(
                [new("North", "West", "CIR-1", "Carrier", ["WO-2"]), new("South", "East", "WO-2", "Carrier", ["CIR-1"])],
                9,
                CancellationToken.None);

            Assert.Equal(new[] { 0, 1 }, fiber.Select(row => row.SortOrder));
            Assert.Equal(new[] { 0 }, onpage.Select(row => row.SortOrder));
            Assert.Equal(new[] { "WO-2" }, network[0].AssociatedCircuitNetworkOrderIds);
            Assert.Equal(new[] { "CIR-1" }, network[1].AssociatedCircuitNetworkOrderIds);
            Assert.Equal(fiber, await store.GetFiberAsync(CancellationToken.None));
            Assert.Equal(onpage, await store.GetOnpageAsync(CancellationToken.None));
            var storedNetwork = await store.GetNetworkOrdersAsync(CancellationToken.None);
            Assert.Equal(network.Select(row => row.CircuitNetworkOrderId), storedNetwork.Select(row => row.CircuitNetworkOrderId));
            Assert.Equal(network.SelectMany(row => row.AssociatedCircuitNetworkOrderIds),
                storedNetwork.SelectMany(row => row.AssociatedCircuitNetworkOrderIds));

            await using var auditConnection = connections.Create();
            await auditConnection.OpenAsync();
            await using var audit = auditConnection.CreateCommand();
            audit.CommandText = "SELECT actor_user_id, event_type, event_detail FROM account_audit_events ORDER BY id";
            await using var reader = await audit.ExecuteReaderAsync();
            var expected = new[]
            {
                ("fiber_email_contacts_replaced", 2),
                ("onpage_email_contacts_replaced", 1),
                ("network_order_circuits_replaced", 2),
            };
            foreach (var (eventType, count) in expected)
            {
                Assert.True(await reader.ReadAsync());
                Assert.Equal(9, reader.GetInt32(0));
                Assert.Equal(eventType, reader.GetString(1));
                using var detail = JsonDocument.Parse(reader.GetString(2));
                Assert.Equal(count, detail.RootElement.GetProperty("row_count").GetInt32());
                Assert.DoesNotContain("@", reader.GetString(2), StringComparison.Ordinal);
            }
            Assert.False(await reader.ReadAsync());
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
