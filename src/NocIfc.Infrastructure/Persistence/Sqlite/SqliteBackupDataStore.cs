using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteBackupDataStore(SqliteConnectionFactory connections) : IBackupDataStore
{
    private static readonly string[] ModelTables =
    [
        "users", "roles", "saved_reports", "feed_sources", "keywords", "system_config", "shift_logs",
        "software_assets", "hardware_assets", "internal_risk_snapshots", "articles", "extracted_iocs",
        "cve_items", "elastic_events", "daily_briefings", "daily_threat_scores", "regional_hazards",
        "regional_outages", "cloud_outages", "bgp_anomalies", "solarwinds_alerts", "timeline_events",
        "monitored_locations", "monitored_location_contacts", "crime_incidents", "geojson_cache",
        "user_weather_prefs", "node_aliases",
    ];
    private static readonly HashSet<string> ModelTableSet = new(ModelTables, StringComparer.Ordinal);

    public async Task<JsonObject> GetLegacySettingsBackupAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var result = new JsonObject
        {
            ["keywords"] = await SelectObjectsAsync(connection,
                "SELECT word, weight FROM keywords", ["word", "weight"], cancellationToken),
            ["feeds"] = await SelectObjectsAsync(connection,
                "SELECT url, name FROM feed_sources", ["url", "name"], cancellationToken),
            ["locations"] = await SelectObjectsAsync(connection,
                "SELECT name, lat, lon, loc_type, priority FROM monitored_locations", ["name", "lat", "lon", "type", "prio"], cancellationToken),
            ["aliases"] = await SelectObjectsAsync(connection,
                "SELECT node_pattern, mapped_location_name, confidence_score, is_verified FROM node_aliases",
                ["pattern", "mapped", "conf", "ver"], cancellationToken, ["", "", "", "BOOLEAN"]),
        };
        return result;
    }

    public async Task<IReadOnlyDictionary<string, int>> RestoreLegacySettingsBackupAsync(
        JsonObject data,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var added = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["kw"] = 0,
            ["feeds"] = 0,
            ["locs"] = 0,
            ["alias"] = 0,
        };
        await RestoreLegacyRowsAsync(connection, transaction, data["keywords"], "keywords", "word",
            ["word", "weight"], "kw", added, cancellationToken);
        await RestoreLegacyRowsAsync(connection, transaction, data["feeds"], "feed_sources", "url",
            ["url", "name"], "feeds", added, cancellationToken);
        await RestoreLegacyRowsAsync(connection, transaction, data["locations"], "monitored_locations", "name",
            ["name", "lat", "lon", "loc_type", "priority"], "locs", added, cancellationToken,
            row =>
            {
                if (row.TryGetPropertyValue("type", out var type)) row["loc_type"] = type?.DeepClone();
                if (row.TryGetPropertyValue("prio", out var priority)) row["priority"] = priority?.DeepClone();
            });
        await RestoreLegacyRowsAsync(connection, transaction, data["aliases"], "node_aliases", "node_pattern",
            ["node_pattern", "mapped_location_name", "confidence_score", "is_verified"], "alias", added,
            cancellationToken,
            row =>
            {
                if (row.TryGetPropertyValue("pattern", out var pattern)) row["node_pattern"] = pattern?.DeepClone();
                if (row.TryGetPropertyValue("mapped", out var mapped)) row["mapped_location_name"] = mapped?.DeepClone();
                if (row.TryGetPropertyValue("conf", out var confidence)) row["confidence_score"] = confidence?.DeepClone();
                if (row.TryGetPropertyValue("ver", out var verified)) row["is_verified"] = verified?.DeepClone();
            });
        transaction.Commit();
        return added;
    }

    public async Task<JsonObject> ExportAllTablesAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var result = new JsonObject();
        foreach (var table in ModelTables)
        {
            var rows = await ReadTableAsync(connection, table, cancellationToken);
            result[table] = rows;
        }
        return result;
    }

    public Task<IReadOnlyDictionary<string, int>> ImportAllTablesAsync(
        JsonObject data,
        bool merge,
        CancellationToken cancellationToken) =>
        ImportRowsAsync(data, merge, clearExisting: true, cancellationToken);

    public async Task<IReadOnlyDictionary<string, int>> ImportDatabaseRowsAsync(
        string databasePath,
        CancellationToken cancellationToken)
    {
        if (!File.Exists(databasePath)) throw new ArgumentException("Uploaded SQLite file was not found.");
        await using var source = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        await source.OpenAsync(cancellationToken);
        var sourceTables = new HashSet<string>(StringComparer.Ordinal);
        await using (var query = source.CreateCommand())
        {
            query.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) sourceTables.Add(reader.GetString(0));
        }
        await using var target = connections.Create();
        await target.OpenAsync(cancellationToken);
        await using (var foreignKeys = target.CreateCommand())
        {
            foreignKeys.CommandText = "PRAGMA foreign_keys=OFF";
            await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
        }
        using var transaction = target.BeginTransaction();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        try
        {
            foreach (var table in ModelTables)
            {
                if (!sourceTables.Contains(table)
                    || !await TableExistsAsync(target, transaction, table, cancellationToken))
                {
                    counts[table] = 0;
                    continue;
                }

                var sourceColumns = await GetColumnsAsync(source, null, table, cancellationToken);
                var targetColumns = await GetColumnsAsync(target, transaction, table, cancellationToken);
                await using var query = source.CreateCommand();
                query.CommandText = $"SELECT * FROM {QuoteIdentifier(table)}";
                await using var reader = await query.ExecuteReaderAsync(cancellationToken);
                var inserted = 0;
                while (await reader.ReadAsync(cancellationToken))
                {
                    var row = new JsonObject();
                    for (var index = 0; index < sourceColumns.Count; index++)
                    {
                        row[sourceColumns[index].Name] = ToJsonNode(reader, index, sourceColumns[index].Type);
                    }
                    if (table == "monitored_location_contacts"
                        && !await ValidateContactRowAsync(target, transaction, row, cancellationToken))
                    {
                        continue;
                    }
                    await InsertRowAsync(target, transaction, table, targetColumns, row, cancellationToken);
                    inserted++;
                }
                counts[table] = inserted;
            }
            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
        finally
        {
            await using var foreignKeys = target.CreateCommand();
            foreignKeys.CommandText = "PRAGMA foreign_keys=ON";
            await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
        }
        return counts;
    }

    private async Task<IReadOnlyDictionary<string, int>> ImportRowsAsync(
        JsonObject data,
        bool merge,
        bool clearExisting,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using (var foreignKeys = connection.CreateCommand())
        {
            foreignKeys.CommandText = "PRAGMA foreign_keys=OFF";
            await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
        }
        using var transaction = connection.BeginTransaction();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        try
        {
            foreach (var table in ModelTables)
            {
                var rows = data[table] as JsonArray;
                if (rows is null || rows.Count == 0)
                {
                    counts[table] = 0;
                    continue;
                }
                var columns = await GetColumnsAsync(connection, transaction, table, cancellationToken);
                if (!clearExisting && rows.Count > 0 && !await TableExistsAsync(connection, transaction, table, cancellationToken))
                {
                    counts[table] = 0;
                    continue;
                }
                if (!merge && clearExisting)
                {
                    if (table == "monitored_locations")
                    {
                        await ExecuteAsync(connection, transaction, "DELETE FROM monitored_location_contacts", cancellationToken);
                    }
                    await ExecuteAsync(connection, transaction, $"DELETE FROM {QuoteIdentifier(table)}", cancellationToken);
                }
                var inserted = 0;
                foreach (var rowNode in rows)
                {
                    if (rowNode is not JsonObject row) throw new ArgumentException($"Rows in {table} must be objects.");
                    if (table == "monitored_location_contacts" && !await ValidateContactRowAsync(connection, transaction, row, cancellationToken))
                    {
                        continue;
                    }
                    var idColumn = columns.FirstOrDefault(column => column.Name == "id");
                    if (merge && row["id"] is { } idNode && idColumn is not null
                        && await RecordExistsAsync(connection, transaction, table,
                            ToSqliteValue(idNode, idColumn.Type), cancellationToken))
                    {
                        continue;
                    }
                    await InsertRowAsync(connection, transaction, table, columns, row, cancellationToken);
                    inserted++;
                }
                counts[table] = inserted;
            }
            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
        finally
        {
            await using var foreignKeys = connection.CreateCommand();
            foreignKeys.CommandText = "PRAGMA foreign_keys=ON";
            await foreignKeys.ExecuteNonQueryAsync(cancellationToken);
        }
        return counts;
    }

    private async Task<bool> ValidateContactRowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        JsonObject row,
        CancellationToken cancellationToken)
    {
        var contactId = ReadInteger(row["monitored_location_id"]);
        if (contactId is null or <= 0) throw new ArgumentException("Imported site contact requires a positive monitored_location_id.");
        if (!await RecordExistsAsync(connection, transaction, "monitored_locations", contactId.Value, cancellationToken))
        {
            throw new ArgumentException("Imported site contact references an unknown monitored location.");
        }
        var sortOrder = row["sort_order"] is null ? 0 : ReadInteger(row["sort_order"]);
        if (sortOrder is null or < 0) throw new ArgumentException("Imported site contact sort_order must be a non-negative integer.");
        var name = SiteContactRules.NormalizeOptional("name", ReadOptionalString(row["name"]));
        var phone = SiteContactRules.NormalizeOptional("phone", ReadOptionalString(row["phone"]));
        var email = SiteContactRules.NormalizeOptional("email", ReadOptionalString(row["email"]));
        row["name"] = name;
        row["phone"] = phone;
        row["email"] = email;
        row["sort_order"] = sortOrder.Value;
        return name is not null || phone is not null || email is not null;
    }

    private async Task<JsonArray> ReadTableAsync(
        SqliteConnection connection,
        string table,
        CancellationToken cancellationToken)
    {
        if (!ModelTableSet.Contains(table) || !await TableExistsAsync(connection, null, table, cancellationToken)) return [];
        var columns = await GetColumnsAsync(connection, null, table, cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = $"SELECT * FROM {QuoteIdentifier(table)}";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new JsonArray();
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new JsonObject();
            for (var index = 0; index < columns.Count; index++)
            {
                row[columns[index].Name] = ToJsonNode(reader, index, columns[index].Type);
            }
            rows.Add(row);
        }
        return rows;
    }

    private async Task InsertRowAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        IReadOnlyList<ColumnInfo> columns,
        JsonObject row,
        CancellationToken cancellationToken)
    {
        var values = columns.Where(column => row.ContainsKey(column.Name)).ToArray();
        if (values.Length == 0)
        {
            await ExecuteAsync(connection, transaction, $"INSERT INTO {QuoteIdentifier(table)} DEFAULT VALUES", cancellationToken);
            return;
        }
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var names = new List<string>();
        var parameters = new List<string>();
        foreach (var column in values)
        {
            var parameter = $"$v{parameters.Count}";
            names.Add(QuoteIdentifier(column.Name));
            parameters.Add(parameter);
            command.Parameters.AddWithValue(parameter, ToSqliteValue(row[column.Name], column.Type));
        }
        command.CommandText = $"INSERT INTO {QuoteIdentifier(table)} ({string.Join(", ", names)}) VALUES ({string.Join(", ", parameters)})";
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static JsonNode? ToJsonNode(SqliteDataReader reader, int ordinal, string type)
    {
        if (reader.IsDBNull(ordinal)) return null;
        var value = reader.GetValue(ordinal);
        if (type.Contains("JSON", StringComparison.OrdinalIgnoreCase))
        {
            try { return JsonNode.Parse(Convert.ToString(value, CultureInfo.InvariantCulture) ?? "null"); }
            catch (JsonException) { return JsonValue.Create(Convert.ToString(value, CultureInfo.InvariantCulture)); }
        }
        if (type.Contains("BOOL", StringComparison.OrdinalIgnoreCase)) return JsonValue.Create(Convert.ToInt64(value, CultureInfo.InvariantCulture) != 0);
        if (type.Contains("DATE", StringComparison.OrdinalIgnoreCase))
        {
            var text = Convert.ToString(value, CultureInfo.InvariantCulture);
            return DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date)
                ? JsonValue.Create(date.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture))
                : JsonValue.Create(text);
        }
        if (value is byte[] bytes) return JsonValue.Create(Convert.ToBase64String(bytes));
        return JsonSerializer.SerializeToNode(value);
    }

    private static object ToSqliteValue(JsonNode? node, string type)
    {
        if (node is null) return DBNull.Value;
        if (type.Contains("JSON", StringComparison.OrdinalIgnoreCase)) return node.ToJsonString();
        if (type.Contains("BOOL", StringComparison.OrdinalIgnoreCase))
        {
            if (node is JsonValue boolValue && boolValue.TryGetValue<bool>(out var boolean)) return boolean;
            if (node is JsonValue intValue && intValue.TryGetValue<int>(out var integer)) return integer != 0;
        }
        if (type.Contains("DATE", StringComparison.OrdinalIgnoreCase))
        {
            var text = ReadOptionalString(node);
            if (DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var date))
            {
                return date.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
            }
        }
        if (type.Contains("BLOB", StringComparison.OrdinalIgnoreCase) && node is JsonValue binary
            && binary.TryGetValue<string>(out var base64))
        {
            try { return Convert.FromBase64String(base64); }
            catch (FormatException) { throw new ArgumentException("Imported binary data must be base64 encoded."); }
        }
        if (node is JsonValue scalar)
        {
            if (scalar.TryGetValue<bool>(out var boolValue)) return boolValue;
            if (scalar.TryGetValue<int>(out var int32)) return int32;
            if (scalar.TryGetValue<long>(out var int64)) return int64;
            if (scalar.TryGetValue<double>(out var dbl)) return dbl;
            if (scalar.TryGetValue<string>(out var text)) return text;
        }
        return node.ToJsonString();
    }

    private static string? ReadOptionalString(JsonNode? node)
    {
        if (node is null) return null;
        return node is JsonValue scalar && scalar.TryGetValue<string>(out var value)
            ? value
            : throw new ArgumentException("Imported text fields must be strings or null.");
    }

    private static int? ReadInteger(JsonNode? node)
    {
        if (node is null) return null;
        if (node is JsonValue scalar && scalar.TryGetValue<int>(out var value)) return value;
        return null;
    }

    private static object ToBasicSqliteValue(JsonNode? node)
    {
        if (node is null) return DBNull.Value;
        if (node is not JsonValue scalar) return node.ToJsonString();
        if (scalar.TryGetValue<bool>(out var boolean)) return boolean;
        if (scalar.TryGetValue<int>(out var int32)) return int32;
        if (scalar.TryGetValue<long>(out var int64)) return int64;
        if (scalar.TryGetValue<double>(out var number)) return number;
        if (scalar.TryGetValue<string>(out var text)) return text;
        return node.ToJsonString();
    }

    private static string QuoteIdentifier(string identifier) => $"\"{identifier.Replace("\"", "\"\"")}\"";

    private static async Task<bool> TableExistsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name LIMIT 1";
        command.Parameters.AddWithValue("$name", table);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task<IReadOnlyList<ColumnInfo>> GetColumnsAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string table,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"PRAGMA table_info({QuoteIdentifier(table)})";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var columns = new List<ColumnInfo>();
        while (await reader.ReadAsync(cancellationToken)) columns.Add(new ColumnInfo(reader.GetString(1), reader.GetString(2)));
        return columns;
    }

    private static async Task<bool> RecordExistsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        object id,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT 1 FROM {QuoteIdentifier(table)} WHERE id=$id LIMIT 1";
        command.Parameters.AddWithValue("$id", id);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    private static async Task ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string sql,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<JsonArray> SelectObjectsAsync(
        SqliteConnection connection,
        string queryText,
        IReadOnlyList<string> outputNames,
        CancellationToken cancellationToken,
        IReadOnlyList<string>? types = null)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = queryText;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var rows = new JsonArray();
        while (await reader.ReadAsync(cancellationToken))
        {
            var row = new JsonObject();
            for (var index = 0; index < outputNames.Count; index++)
            {
                row[outputNames[index]] = ToJsonNode(reader, index, types is null ? "" : types[index]);
            }
            rows.Add(row);
        }
        return rows;
    }

    private static async Task RestoreLegacyRowsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        JsonNode? value,
        string table,
        string uniqueColumn,
        IReadOnlyList<string> columns,
        string countKey,
        Dictionary<string, int> counts,
        CancellationToken cancellationToken,
        Action<JsonObject>? normalize = null)
    {
        if (value is null)
        {
            counts[countKey] = 0;
            return;
        }
        if (value is not JsonArray rows) throw new ArgumentException($"{countKey} must be a list.");
        var added = 0;
        foreach (var item in rows)
        {
            if (item is not JsonObject row) throw new ArgumentException($"{countKey} entries must be objects.");
            normalize?.Invoke(row);
            if (row[uniqueColumn] is not JsonValue uniqueValue || !uniqueValue.TryGetValue<string>(out var unique))
            {
                throw new ArgumentException($"{uniqueColumn} is required in {countKey} entries.");
            }
            await using var exists = connection.CreateCommand();
            exists.Transaction = transaction;
            exists.CommandText = $"SELECT 1 FROM {QuoteIdentifier(table)} WHERE {QuoteIdentifier(uniqueColumn)}=$value LIMIT 1";
            exists.Parameters.AddWithValue("$value", unique);
            if (await exists.ExecuteScalarAsync(cancellationToken) is not null) continue;
            var values = columns.Select(column => (Name: column, Value: row[column]))
                .Where(pair => pair.Value is not null).ToArray();
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            var names = new List<string>();
            var parameters = new List<string>();
            foreach (var (column, node) in values)
            {
                var parameter = $"$v{parameters.Count}";
                names.Add(QuoteIdentifier(column));
                parameters.Add(parameter);
                insert.Parameters.AddWithValue(parameter, ToBasicSqliteValue(node));
            }
            insert.CommandText = $"INSERT INTO {QuoteIdentifier(table)} ({string.Join(", ", names)}) VALUES ({string.Join(", ", parameters)})";
            await insert.ExecuteNonQueryAsync(cancellationToken);
            added++;
        }
        counts[countKey] = added;
    }

    private sealed record ColumnInfo(string Name, string Type);
}
