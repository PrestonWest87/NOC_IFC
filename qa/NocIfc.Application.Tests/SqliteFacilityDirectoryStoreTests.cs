using System.Globalization;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using NocIfc.Infrastructure.Persistence.Sqlite;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SqliteFacilityDirectoryStoreTests
{
    [Fact]
    public async Task ImportsUpdatesAndPreservesSameNameContactsAcrossReplacement()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"nocifc-facilities-{Guid.NewGuid():N}.sqlite");
        using (File.Create(databasePath)) { }
        try
        {
            var connections = new SqliteConnectionFactory($"sqlite:///{databasePath}");
            await using (var connection = connections.Create())
            {
                await connection.OpenAsync();
                await using var setup = connection.CreateCommand();
                setup.CommandText = """
                    CREATE TABLE monitored_locations (
                        id INTEGER PRIMARY KEY, name TEXT UNIQUE, lat REAL, lon REAL,
                        loc_type TEXT, district TEXT, priority TEXT, current_spc_risk TEXT,
                        last_updated DATETIME, under_maintenance INTEGER, maintenance_etr DATETIME,
                        maintenance_reason TEXT, last_auto_ticket DATETIME, last_escalation_ticket DATETIME,
                        last_auto_dispatch DATETIME, last_escalation_dispatch DATETIME,
                        status_modified_by TEXT, status_modified_at DATETIME
                    );
                    CREATE TABLE monitored_location_contacts (
                        id INTEGER PRIMARY KEY, monitored_location_id INTEGER NOT NULL,
                        name TEXT, phone TEXT, email TEXT, sort_order INTEGER NOT NULL
                    );
                    INSERT INTO monitored_locations (
                        id, name, lat, lon, loc_type, district, priority, current_spc_risk,
                        last_updated, under_maintenance
                    ) VALUES (1, 'Site A', 34, -92, 'NOC', 'Central', 'P2', 'None', $now, 0);
                    INSERT INTO monitored_locations (
                        id, name, lat, lon, loc_type, district, priority, current_spc_risk,
                        last_updated, under_maintenance
                    ) VALUES (2, 'Site B', 35, -91, 'SCADA', 'East', 'P1', 'None', $now, 0);
                    INSERT INTO monitored_location_contacts VALUES (1, 1, 'NOC Desk', '501-555-0100', 'desk@example.com', 0);
                    """;
                setup.Parameters.AddWithValue("$now", FormatDate(DateTime.UtcNow));
                await setup.ExecuteNonQueryAsync();
            }

            var store = new SqliteFacilityDirectoryStore(connections);
            var initial = await store.GetLocationsAsync(CancellationToken.None);
            Assert.Equal(new[] { "Site A", "Site B" }, initial.Select(location => location.Name));
            Assert.Equal("NOC", initial[0].LocationType);
            var contact = Assert.Single(await store.GetSiteContactsAsync(1, CancellationToken.None) ?? []);
            Assert.Equal("NOC Desk", contact.Name);

            var replacedCount = await store.ImportLocationsAsync(
            [
                new("Site A", 34.5, -92.5, "NOC", null, "Central", "P1"),
                new("Site C", 36, -90, null, "POWER", null, null),
            ],
                "replace",
                CancellationToken.None);
            Assert.Equal(2, replacedCount);
            var replaced = await store.GetLocationsAsync(CancellationToken.None);
            Assert.Equal(new[] { "Site A", "Site C" }, replaced.Select(location => location.Name));
            Assert.Equal((double?)34.5, replaced[0].Latitude);
            Assert.Equal("POWER", replaced[1].LocationType);
            Assert.Equal("Central", replaced[1].District);
            Assert.Equal("P3-Moderate", replaced[1].Priority);
            Assert.Equal("NOC Desk", Assert.Single(await store.GetSiteContactsAsync(
                replaced[0].Id, CancellationToken.None) ?? []).Name);

            var upsertedCount = await store.ImportLocationsAsync(
            [
                new("Site A", 40, -80, null, "UPDATED", "North", "P0"),
                new("Site D", 30, -90, null, null, null, null),
            ],
                "upsert",
                CancellationToken.None);
            Assert.Equal(2, upsertedCount);
            var updated = (await store.GetLocationsAsync(CancellationToken.None)).Single(location => location.Name == "Site A");
            Assert.Equal((double?)40, updated.Latitude);
            Assert.Equal("UPDATED", updated.LocationType);
            Assert.Equal("North", updated.District);
            Assert.Equal("P0", updated.Priority);
            Assert.Equal("NOC Desk", Assert.Single(await store.GetSiteContactsAsync(
                updated.Id, CancellationToken.None) ?? []).Name);

            await store.UpdateLocationsAsync(
                [new MonitoredLocationEditRow(updated.Id, "Renamed Site", "FIBER", null, "West", "P3", 0, -85)],
                CancellationToken.None);
            var edited = (await store.GetLocationsAsync(CancellationToken.None)).Single(location => location.Id == updated.Id);
            Assert.Equal("Renamed Site", edited.Name);
            Assert.Equal("FIBER", edited.LocationType);
            Assert.Equal("West", edited.District);
            Assert.Equal("P3", edited.Priority);
            Assert.Equal((double?)40, edited.Latitude);
            Assert.Equal((double?)-85, edited.Longitude);
        }
        finally
        {
            File.Delete(databasePath);
        }
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
