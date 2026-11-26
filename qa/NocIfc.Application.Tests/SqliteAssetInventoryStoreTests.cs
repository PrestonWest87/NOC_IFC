using NocIfc.Application.Features.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteAssetInventoryStoreTests
{
    [Fact]
    public async Task ReplacesSoftwareAndHardwareRowsAndAppliesModelDefaults()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-asset-inventory-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE software_assets (id INTEGER PRIMARY KEY, name TEXT, last_updated DATETIME);
                    CREATE TABLE hardware_assets (
                        id INTEGER PRIMARY KEY, ip_address TEXT NOT NULL, asset_name TEXT, host_type TEXT,
                        ip_addresses TEXT, operating_system TEXT, os_architecture TEXT, os_family TEXT,
                        os_product TEXT, os_vendor TEXT, os_version TEXT, instances INTEGER,
                        critical_instances INTEGER, severe_instances INTEGER, moderate_instances INTEGER,
                        vulnerabilities INTEGER, critical_vulnerabilities INTEGER, severe_vulnerabilities INTEGER,
                        moderate_vulnerabilities INTEGER, exploit_count INTEGER, malware_count INTEGER,
                        raw_risk_score REAL, risk_score REAL, last_updated DATETIME
                    );
                    INSERT INTO software_assets VALUES (1, 'old package', '2025-01-01 00:00:00');
                    INSERT INTO hardware_assets (id, ip_address, instances) VALUES (1, '192.0.2.1', 99);
                    """;
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteAssetInventoryStore(connections);
            await store.ReplaceSoftwareAssetsAsync(["Router OS", "Switch OS"], CancellationToken.None);
            await store.ReplaceHardwareAssetsAsync(
            [
                new HardwareAssetImportRow(new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["ip_address"] = "192.0.2.10",
                    ["asset_name"] = "Core Router",
                    ["instances"] = 4,
                    ["risk_score"] = 72.5,
                }),
            ],
                CancellationToken.None);

            await using var verify = connections.Create();
            await verify.OpenAsync();
            await using (var software = verify.CreateCommand())
            {
                software.CommandText = "SELECT name FROM software_assets ORDER BY id";
                await using var reader = await software.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("Router OS", reader.GetString(0));
                Assert.True(await reader.ReadAsync());
                Assert.Equal("Switch OS", reader.GetString(0));
                Assert.False(await reader.ReadAsync());
            }
            await using (var hardware = verify.CreateCommand())
            {
                hardware.CommandText = "SELECT ip_address, asset_name, instances, critical_instances, risk_score FROM hardware_assets";
                await using var reader = await hardware.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal("192.0.2.10", reader.GetString(0));
                Assert.Equal("Core Router", reader.GetString(1));
                Assert.Equal(4, reader.GetInt32(2));
                Assert.Equal(0, reader.GetInt32(3));
                Assert.Equal(72.5, reader.GetDouble(4));
            }
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
