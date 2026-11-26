using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteFacilityDirectoryStore(SqliteConnectionFactory connections) : IFacilityDirectoryStore
{
    private const string LocationColumns = """
        id, name, lat, lon, loc_type, district, priority, current_spc_risk, last_updated,
        under_maintenance, maintenance_etr, maintenance_reason, last_auto_ticket,
        last_escalation_ticket, last_auto_dispatch, last_escalation_dispatch,
        status_modified_by, status_modified_at
        """;

    public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) =>
        GetLocationsAsync(cancellationToken);

    public async Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT {LocationColumns} FROM monitored_locations ORDER BY id";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var locations = new List<MonitoredLocationEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            locations.Add(ReadLocation(reader));
        }
        return locations;
    }

    public async Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(
        int locationId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        if (!await LocationExistsAsync(connection, null, locationId, cancellationToken))
        {
            return null;
        }
        return await ReadSiteContactsAsync(connection, null, locationId, cancellationToken);
    }

    public async Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
        int locationId,
        IReadOnlyList<MonitoredLocationContactValue> contacts,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        if (!await LocationExistsAsync(connection, transaction, locationId, cancellationToken))
        {
            return null;
        }

        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM monitored_location_contacts WHERE monitored_location_id = $location_id";
            delete.Parameters.AddWithValue("$location_id", locationId);
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        for (var index = 0; index < contacts.Count; index++)
        {
            var contact = contacts[index];
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO monitored_location_contacts
                    (monitored_location_id, name, phone, email, sort_order)
                VALUES ($location_id, $name, $phone, $email, $sort_order)
                """;
            insert.Parameters.AddWithValue("$location_id", locationId);
            insert.Parameters.AddWithValue("$name", (object?)contact.Name ?? DBNull.Value);
            insert.Parameters.AddWithValue("$phone", (object?)contact.Phone ?? DBNull.Value);
            insert.Parameters.AddWithValue("$email", (object?)contact.Email ?? DBNull.Value);
            insert.Parameters.AddWithValue("$sort_order", index);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return await ReadSiteContactsAsync(connection, null, locationId, cancellationToken);
    }

    public async Task<int> ImportLocationsAsync(
        IReadOnlyList<MonitoredLocationImportRow> locations,
        string mode,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var contactsBySite = mode == "replace"
            ? await ReadContactsBySiteAsync(connection, transaction, cancellationToken)
            : new Dictionary<string, List<MonitoredLocationContactEntry>>(StringComparer.Ordinal);
        var existingNames = new HashSet<string>(StringComparer.Ordinal);
        await using (var existing = connection.CreateCommand())
        {
            existing.Transaction = transaction;
            existing.CommandText = "SELECT name FROM monitored_locations";
            await using var reader = await existing.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (!reader.IsDBNull(0))
                {
                    existingNames.Add(reader.GetString(0));
                }
            }
        }

        if (mode == "replace")
        {
            await using var deleteContacts = connection.CreateCommand();
            deleteContacts.Transaction = transaction;
            deleteContacts.CommandText = "DELETE FROM monitored_location_contacts";
            await deleteContacts.ExecuteNonQueryAsync(cancellationToken);
            await using var deleteLocations = connection.CreateCommand();
            deleteLocations.Transaction = transaction;
            deleteLocations.CommandText = "DELETE FROM monitored_locations";
            await deleteLocations.ExecuteNonQueryAsync(cancellationToken);
            existingNames.Clear();
        }

        var count = 0;
        foreach (var location in locations)
        {
            if (string.IsNullOrEmpty(location.Name) || location.Latitude is null || location.Longitude is null)
            {
                continue;
            }
            var locationType = !string.IsNullOrEmpty(location.Type)
                ? location.Type
                : !string.IsNullOrEmpty(location.LocationType) ? location.LocationType : "General";
            var district = location.District ?? "Central";
            var priority = location.Priority ?? "P3-Moderate";
            if (mode == "upsert" && existingNames.Contains(location.Name))
            {
                await UpdateByNameAsync(
                    connection, transaction, location.Name, location.Latitude.Value,
                    location.Longitude.Value, locationType, district, priority, cancellationToken);
                count++;
            }
            else if (!existingNames.Contains(location.Name))
            {
                await InsertLocationAsync(
                    connection, transaction, location.Name, location.Latitude.Value,
                    location.Longitude.Value, locationType, district, priority, cancellationToken);
                existingNames.Add(location.Name);
                count++;
            }
        }

        if (contactsBySite.Count > 0)
        {
            foreach (var (siteName, contacts) in contactsBySite)
            {
                if (!existingNames.Contains(siteName))
                {
                    continue;
                }
                var locationId = await ReadLocationIdByNameAsync(connection, transaction, siteName, cancellationToken);
                if (locationId is null)
                {
                    continue;
                }
                foreach (var contact in contacts)
                {
                    await InsertContactAsync(
                        connection, transaction, locationId.Value, contact.Name, contact.Phone,
                        contact.Email, contact.SortOrder, cancellationToken);
                }
            }
        }
        transaction.Commit();
        return count;
    }

    public async Task UpdateLocationsAsync(
        IReadOnlyList<MonitoredLocationEditRow> locations,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        foreach (var update in locations)
        {
            if (update.Id is null)
            {
                continue;
            }
            string? name;
            double? latitude;
            double? longitude;
            string? locationType;
            string? district;
            string? priority;
            await using (var query = connection.CreateCommand())
            {
                query.Transaction = transaction;
                query.CommandText = "SELECT name, lat, lon, loc_type, district, priority FROM monitored_locations WHERE id = $id";
                query.Parameters.AddWithValue("$id", update.Id.Value);
                await using var reader = await query.ExecuteReaderAsync(cancellationToken);
                if (!await reader.ReadAsync(cancellationToken))
                {
                    continue;
                }
                name = ReadString(reader, 0);
                latitude = reader.IsDBNull(1) ? null : reader.GetDouble(1);
                longitude = reader.IsDBNull(2) ? null : reader.GetDouble(2);
                locationType = ReadString(reader, 3);
                district = ReadString(reader, 4);
                priority = ReadString(reader, 5);
            }

            name = FirstTruthy(update.Name, name);
            locationType = FirstTruthy(update.LocationType, update.Type, locationType);
            district = FirstTruthy(update.District, district);
            priority = FirstTruthy(update.Priority, priority);
            if (update.Latitude is { } updatedLatitude && updatedLatitude != 0)
            {
                latitude = updatedLatitude;
            }
            if (update.Longitude is { } updatedLongitude && updatedLongitude != 0)
            {
                longitude = updatedLongitude;
            }

            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                UPDATE monitored_locations
                SET name = $name, lat = $lat, lon = $lon, loc_type = $loc_type,
                    district = $district, priority = $priority
                WHERE id = $id
                """;
            command.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
            command.Parameters.AddWithValue("$lat", (object?)latitude ?? DBNull.Value);
            command.Parameters.AddWithValue("$lon", (object?)longitude ?? DBNull.Value);
            command.Parameters.AddWithValue("$loc_type", (object?)locationType ?? DBNull.Value);
            command.Parameters.AddWithValue("$district", (object?)district ?? DBNull.Value);
            command.Parameters.AddWithValue("$priority", (object?)priority ?? DBNull.Value);
            command.Parameters.AddWithValue("$id", update.Id.Value);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static async Task InsertLocationAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string name,
        double latitude,
        double longitude,
        string locationType,
        string district,
        string priority,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO monitored_locations
                (name, lat, lon, loc_type, district, priority, current_spc_risk, last_updated, under_maintenance)
            VALUES ($name, $lat, $lon, $loc_type, $district, $priority, 'None', $last_updated, 0)
            """;
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$lat", latitude);
        command.Parameters.AddWithValue("$lon", longitude);
        command.Parameters.AddWithValue("$loc_type", locationType);
        command.Parameters.AddWithValue("$district", district);
        command.Parameters.AddWithValue("$priority", priority);
        command.Parameters.AddWithValue("$last_updated", FormatDate(DateTime.UtcNow));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task UpdateByNameAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string name,
        double latitude,
        double longitude,
        string locationType,
        string district,
        string priority,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE monitored_locations
            SET lat = $lat, lon = $lon, loc_type = $loc_type, district = $district, priority = $priority
            WHERE name = $name
            """;
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$lat", latitude);
        command.Parameters.AddWithValue("$lon", longitude);
        command.Parameters.AddWithValue("$loc_type", locationType);
        command.Parameters.AddWithValue("$district", district);
        command.Parameters.AddWithValue("$priority", priority);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<long?> ReadLocationIdByNameAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string siteName,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT id FROM monitored_locations WHERE name = $name LIMIT 1";
        command.Parameters.AddWithValue("$name", siteName);
        var id = await command.ExecuteScalarAsync(cancellationToken);
        return id is null or DBNull ? null : Convert.ToInt64(id, CultureInfo.InvariantCulture);
    }

    private static async Task<Dictionary<string, List<MonitoredLocationContactEntry>>> ReadContactsBySiteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, List<MonitoredLocationContactEntry>>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT locations.name, contacts.id, contacts.name, contacts.phone,
                   contacts.email, contacts.sort_order
            FROM monitored_location_contacts AS contacts
            JOIN monitored_locations AS locations ON locations.id = contacts.monitored_location_id
            ORDER BY contacts.sort_order, contacts.id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            if (reader.IsDBNull(0))
            {
                continue;
            }
            var siteName = reader.GetString(0);
            if (!result.TryGetValue(siteName, out var contacts))
            {
                contacts = [];
                result[siteName] = contacts;
            }
            contacts.Add(new MonitoredLocationContactEntry(
                reader.GetInt32(1), ReadString(reader, 2), ReadString(reader, 3),
                ReadString(reader, 4), reader.GetInt32(5)));
        }
        return result;
    }

    private static async Task InsertContactAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        long locationId,
        string? name,
        string? phone,
        string? email,
        int sortOrder,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO monitored_location_contacts
                (monitored_location_id, name, phone, email, sort_order)
            VALUES ($location_id, $name, $phone, $email, $sort_order)
            """;
        command.Parameters.AddWithValue("$location_id", locationId);
        command.Parameters.AddWithValue("$name", (object?)name ?? DBNull.Value);
        command.Parameters.AddWithValue("$phone", (object?)phone ?? DBNull.Value);
        command.Parameters.AddWithValue("$email", (object?)email ?? DBNull.Value);
        command.Parameters.AddWithValue("$sort_order", sortOrder);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<bool> LocationExistsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        int locationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT 1 FROM monitored_locations WHERE id = $id LIMIT 1";
        command.Parameters.AddWithValue("$id", locationId);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<IReadOnlyList<MonitoredLocationContactEntry>> ReadSiteContactsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        int locationId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT id, name, phone, email, sort_order
            FROM monitored_location_contacts
            WHERE monitored_location_id = $location_id
            ORDER BY sort_order, id
            """;
        command.Parameters.AddWithValue("$location_id", locationId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var contacts = new List<MonitoredLocationContactEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            contacts.Add(new MonitoredLocationContactEntry(
                reader.GetInt32(0), ReadString(reader, 1), ReadString(reader, 2),
                ReadString(reader, 3), reader.GetInt32(4)));
        }
        return contacts;
    }

    private static MonitoredLocationEntry ReadLocation(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        ReadString(reader, 1),
        reader.IsDBNull(2) ? null : reader.GetDouble(2),
        reader.IsDBNull(3) ? null : reader.GetDouble(3),
        ReadString(reader, 4),
        ReadString(reader, 5),
        ReadString(reader, 6),
        ReadString(reader, 7),
        ReadDateTime(reader, 8),
        reader.IsDBNull(9) ? null : reader.GetBoolean(9),
        ReadDateTime(reader, 10),
        ReadString(reader, 11),
        ReadDateTime(reader, 12),
        ReadDateTime(reader, 13),
        ReadDateTime(reader, 14),
        ReadDateTime(reader, 15),
        ReadString(reader, 16),
        ReadDateTime(reader, 17));

    private static string? FirstTruthy(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrEmpty(value));

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
