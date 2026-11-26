using System.Globalization;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteCisaKevStoreTests
{
    [Fact]
    public async Task ReadsRecentKevRowsInDescendingDateOrderWithTheRequestedLimit()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-cisa-kev-{Guid.NewGuid():N}.sqlite");
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
                    CREATE TABLE cve_items (
                        id INTEGER PRIMARY KEY, cve_id TEXT, vendor TEXT, product TEXT,
                        vulnerability_name TEXT, date_added DATETIME, description TEXT,
                        required_action TEXT, due_date TEXT
                    );
                    INSERT INTO cve_items VALUES
                        (1, 'CVE-2026-0001', 'Vendor', 'Product', 'Older', $older, 'Description 1', 'Patch', '2026-12-01'),
                        (2, 'CVE-2026-0002', 'Vendor', 'Product', 'Newer', $newer, 'Description 2', 'Patch', '2026-12-02'),
                        (3, 'CVE-2025-0001', 'Vendor', 'Product', 'Expired', $expired, 'Old', 'Patch', '2025-12-01');
                    """;
                setup.Parameters.AddWithValue("$older", now.AddDays(-8).ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
                setup.Parameters.AddWithValue("$newer", now.AddDays(-2).ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
                setup.Parameters.AddWithValue("$expired", now.AddDays(-35).ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteCisaKevStore(connections);
            var entries = await store.GetRecentAsync(1, now.AddDays(-30), CancellationToken.None);

            var entry = Assert.Single(entries);
            Assert.Equal("CVE-2026-0002", entry.CveId);
            Assert.Equal("Newer", entry.VulnerabilityName);
            Assert.Equal("2026-12-02", entry.DueDate);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }
}
