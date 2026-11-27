using System.Globalization;
using System.Text.Json;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteInternalRiskStoreTests
{
    [Fact]
    public async Task ReadsLatestSnapshotHistoryAndStoredAssetJson()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-internal-risk-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            var now = DateTime.UtcNow;
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE internal_risk_snapshots (
                        id INTEGER PRIMARY KEY, timestamp DATETIME, score REAL, risk_level TEXT,
                        total_assets INTEGER, total_osint_hits INTEGER, critical_osint_hits INTEGER,
                        hw_data_json TEXT, sw_data_json TEXT
                    );
                    CREATE TABLE system_config (id INTEGER PRIMARY KEY, scoring_mode TEXT, last_internal_risk TEXT);
                    INSERT INTO system_config VALUES (1, 'hybrid', NULL);
                    CREATE TABLE hardware_assets (
                        id INTEGER PRIMARY KEY, ip_address TEXT, asset_name TEXT, operating_system TEXT,
                        os_product TEXT, os_vendor TEXT, os_version TEXT
                    );
                    CREATE TABLE software_assets (id INTEGER PRIMARY KEY, name TEXT);
                    INSERT INTO hardware_assets VALUES (1, '192.0.2.1', 'Firewall-1', 'PAN-OS', 'PAN-OS', 'Palo Alto', '11.0');
                    INSERT INTO software_assets VALUES (1, 'Windows Server 2022');
                    INSERT INTO internal_risk_snapshots VALUES
                        (1, $old, 20, 'BLUE', 10, 3, 1, '[]', '[]'),
                        (2, $new, 70, 'ORANGE', 12, 8, 3,
                         '[{"asset_name":"router-1","risk_score":70}]', '[{"name":"package","risk_score":55}]');
                    """;
                setup.Parameters.AddWithValue("$old", FormatDate(now.AddDays(-40)));
                setup.Parameters.AddWithValue("$new", FormatDate(now.AddDays(-1)));
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteInternalRiskStore(connections);
            var latest = Assert.IsType<NocIfc.Domain.Dashboard.InternalRiskSnapshotEntry>(
                await store.GetLatestAsync(CancellationToken.None));
            Assert.Equal(2, latest.Id);
            Assert.Equal("hybrid", latest.ScoringMode);
            Assert.Equal("router-1", latest.HardwareData[0].GetProperty("asset_name").GetString());
            Assert.Equal("package", latest.SoftwareData[0].GetProperty("name").GetString());

            var history = await store.GetHistoryAsync(now.AddDays(-28), CancellationToken.None);
            Assert.Single(history);
            Assert.Equal((double?)70, history[0].Score);
            Assert.Equal("ORANGE", history[0].RiskLevel);

            var inventory = await store.GetAssetInventoryAsync(CancellationToken.None);
            Assert.Equal("192.0.2.1", Assert.Single(inventory.HardwareAssets).IpAddress);
            Assert.Equal("Windows Server 2022", Assert.Single(inventory.SoftwareAssets).Name);

            using var hardwareData = JsonDocument.Parse("[{\"Identifier\":\"Firewall-1\"}]");
            using var softwareData = JsonDocument.Parse("[]");
            await store.SaveSnapshotAsync(new NocIfc.Domain.Dashboard.InternalRiskSnapshotEntry(
                0, now, 2, "YELLOW", 2, 3, 1, hardwareData.RootElement.Clone(), softwareData.RootElement.Clone(), "auto"),
                CancellationToken.None);
            var saved = await store.GetLatestAsync(CancellationToken.None);
            Assert.Equal(3, saved?.Id);
            Assert.Equal("YELLOW", saved?.RiskLevel);
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var mirror = connection.CreateCommand();
                mirror.CommandText = "SELECT last_internal_risk FROM system_config WHERE id=1";
                Assert.Equal("YELLOW", await mirror.ExecuteScalarAsync());
            }
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
