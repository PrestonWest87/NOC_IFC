using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteSettingsReferenceDirectoryStore(SqliteConnectionFactory connections)
    : ISettingsReferenceDirectoryStore
{
    public async Task<IReadOnlyList<FiberEmailContactEntry>> GetFiberAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, name, company, email, phone, sort_order
            FROM fiber_email_contacts
            ORDER BY sort_order, id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var contacts = new List<FiberEmailContactEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            contacts.Add(new FiberEmailContactEntry(
                reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                ReadString(reader, 4), reader.GetInt32(5)));
        }
        return contacts;
    }

    public async Task<IReadOnlyList<FiberEmailContactEntry>> ReplaceFiberAsync(
        IReadOnlyList<FiberEmailContactValue> contacts,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await ReplaceAsync(
            "fiber_email_contacts",
            "fiber_email_contacts_replaced",
            "INSERT INTO fiber_email_contacts (name, company, email, phone, sort_order) VALUES ($name, $company, $email, $phone, $sort_order)",
            contacts.Count,
            actorUserId,
            (command, row, index) =>
            {
                command.Parameters.AddWithValue("$name", row.Name);
                command.Parameters.AddWithValue("$company", row.Company);
                command.Parameters.AddWithValue("$email", row.Email);
                command.Parameters.AddWithValue("$phone", (object?)row.Phone ?? DBNull.Value);
                command.Parameters.AddWithValue("$sort_order", index);
            },
            contacts,
            cancellationToken);
        return await GetFiberAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<OnpageEmailContactEntry>> GetOnpageAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, department, email, sort_order
            FROM onpage_email_contacts
            ORDER BY sort_order, id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var contacts = new List<OnpageEmailContactEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            contacts.Add(new OnpageEmailContactEntry(
                reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetInt32(3)));
        }
        return contacts;
    }

    public async Task<IReadOnlyList<OnpageEmailContactEntry>> ReplaceOnpageAsync(
        IReadOnlyList<OnpageEmailContactValue> contacts,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await ReplaceAsync(
            "onpage_email_contacts",
            "onpage_email_contacts_replaced",
            "INSERT INTO onpage_email_contacts (department, email, sort_order) VALUES ($department, $email, $sort_order)",
            contacts.Count,
            actorUserId,
            (command, row, index) =>
            {
                command.Parameters.AddWithValue("$department", row.Department);
                command.Parameters.AddWithValue("$email", row.Email);
                command.Parameters.AddWithValue("$sort_order", index);
            },
            contacts,
            cancellationToken);
        return await GetOnpageAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<NetworkOrderCircuitEntry>> GetNetworkOrdersAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT id, a_location, z_location, circuit_network_order_id, company,
                   associated_circuit_network_order_ids, sort_order
            FROM network_order_circuits
            ORDER BY sort_order, id
            """;
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var records = new List<NetworkOrderCircuitEntry>();
        while (await reader.ReadAsync(cancellationToken))
        {
            var associations = reader.IsDBNull(5)
                ? Array.Empty<string>()
                : JsonSerializer.Deserialize<string[]>(reader.GetString(5)) ?? [];
            records.Add(new NetworkOrderCircuitEntry(
                reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                reader.GetString(4), associations, reader.GetInt32(6)));
        }
        return records;
    }

    public async Task<IReadOnlyList<NetworkOrderCircuitEntry>> ReplaceNetworkOrdersAsync(
        IReadOnlyList<NetworkOrderCircuitValue> records,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        await ReplaceAsync(
            "network_order_circuits",
            "network_order_circuits_replaced",
            """
            INSERT INTO network_order_circuits
                (a_location, z_location, circuit_network_order_id, company,
                 associated_circuit_network_order_ids, sort_order)
            VALUES ($a_location, $z_location, $circuit_id, $company, $associated, $sort_order)
            """,
            records.Count,
            actorUserId,
            (command, row, index) =>
            {
                command.Parameters.AddWithValue("$a_location", row.ALocation);
                command.Parameters.AddWithValue("$z_location", row.ZLocation);
                command.Parameters.AddWithValue("$circuit_id", row.CircuitNetworkOrderId);
                command.Parameters.AddWithValue("$company", row.Company);
                command.Parameters.AddWithValue("$associated", JsonSerializer.Serialize(row.AssociatedCircuitNetworkOrderIds));
                command.Parameters.AddWithValue("$sort_order", index);
            },
            records,
            cancellationToken);
        return await GetNetworkOrdersAsync(cancellationToken);
    }

    private async Task ReplaceAsync<T>(
        string tableName,
        string eventType,
        string insertSql,
        int rowCount,
        int actorUserId,
        Action<SqliteCommand, T, int> bind,
        IReadOnlyList<T> rows,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = $"DELETE FROM {tableName}";
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        for (var index = 0; index < rows.Count; index++)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = insertSql;
            bind(insert, rows[index], index);
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var audit = connection.CreateCommand())
        {
            audit.Transaction = transaction;
            audit.CommandText = """
                INSERT INTO account_audit_events
                    (actor_user_id, subject_user_id, event_type, event_detail, created_at)
                VALUES ($actor_id, NULL, $event_type, $detail, $created_at)
                """;
            audit.Parameters.AddWithValue("$actor_id", actorUserId);
            audit.Parameters.AddWithValue("$event_type", eventType);
            audit.Parameters.AddWithValue("$detail", JsonSerializer.Serialize(new { row_count = rowCount }));
            audit.Parameters.AddWithValue(
                "$created_at",
                DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
