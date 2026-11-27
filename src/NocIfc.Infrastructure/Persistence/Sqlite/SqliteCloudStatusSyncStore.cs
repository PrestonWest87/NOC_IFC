using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Domain.Threat;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteCloudStatusSyncStore(SqliteConnectionFactory connections)
{
    public async Task<(int AddedCount, int ResolvedCount)> ReconcileAsync(
        IReadOnlyList<CloudOutageEntry> incoming,
        Microsoft365FeedState microsoft365State,
        DateTime purgeBeforeUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await SaveMicrosoft365StateAsync(connection, transaction, microsoft365State, cancellationToken);

        var added = 0;
        var resolved = 0;
        foreach (var providerItems in incoming.GroupBy(item => item.Provider ?? "", StringComparer.Ordinal))
        {
            var items = providerItems.ToArray();
            var byKey = await ReadExistingByKeyAsync(connection, transaction, providerItems.Key, items, cancellationToken);
            var byId = await ReadExistingByIdAsync(connection, transaction, providerItems.Key, items, cancellationToken);
            foreach (var item in items)
            {
                var key = (item.Title, FormatDate(item.UpdatedAt ?? DateTime.UtcNow));
                var existing = !string.IsNullOrEmpty(item.ExternalId)
                    ? byId.GetValueOrDefault(item.ExternalId)
                    : byKey.GetValueOrDefault(key);
                if (existing is null)
                {
                    var inserted = await InsertAsync(connection, transaction, item, cancellationToken);
                    if (inserted is null) continue;
                    added++;
                    byKey[key] = inserted;
                    if (!string.IsNullOrEmpty(item.ExternalId)) byId[item.ExternalId] = inserted;
                    continue;
                }

                if (providerItems.Key == "Microsoft 365")
                {
                    if (existing.UpdatedAt is null || item.UpdatedAt >= existing.UpdatedAt)
                    {
                        await UpdateMicrosoft365Async(connection, transaction, existing.Id, item, cancellationToken);
                        if (existing.IsResolved != true && item.IsResolved == true) resolved++;
                        var updated = ToExisting(existing.Id, item);
                        byKey[key] = updated;
                        if (!string.IsNullOrEmpty(item.ExternalId)) byId[item.ExternalId] = updated;
                    }
                }
                else if (item.IsResolved == true && existing.IsResolved != true)
                {
                    await MarkResolvedAsync(connection, transaction, existing.Id, item.UpdatedAt ?? DateTime.UtcNow, cancellationToken);
                    resolved++;
                    var updated = existing with { IsResolved = true, UpdatedAt = item.UpdatedAt };
                    byKey[key] = updated;
                    if (!string.IsNullOrEmpty(item.ExternalId)) byId[item.ExternalId] = updated;
                }
            }
        }

        await using (var purge = connection.CreateCommand())
        {
            purge.Transaction = transaction;
            purge.CommandText = "DELETE FROM cloud_outages WHERE is_resolved = 1 AND updated_at < $cutoff";
            purge.Parameters.AddWithValue("$cutoff", FormatDate(purgeBeforeUtc));
            await purge.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return (added, resolved);
    }

    private static async Task SaveMicrosoft365StateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Microsoft365FeedState state,
        CancellationToken cancellationToken)
    {
        await using (var ensure = connection.CreateCommand())
        {
            ensure.Transaction = transaction;
            ensure.CommandText = "INSERT OR IGNORE INTO microsoft_365_status_state (id) VALUES (1)";
            await ensure.ExecuteNonQueryAsync(cancellationToken);
        }
        await using var update = connection.CreateCommand();
        update.Transaction = transaction;
        update.CommandText = """
            UPDATE microsoft_365_status_state
            SET last_attempt_at = $attempt,
                last_success_at = COALESCE($success, last_success_at),
                last_duration_ms = $duration,
                last_http_status = $http_status,
                last_error = $error
            WHERE id = 1
            """;
        AddNullableDate(update, "$attempt", state.LastAttemptAt);
        AddNullableDate(update, "$success", state.LastSuccessAt);
        AddNullable(update, "$duration", state.LastDurationMs);
        AddNullable(update, "$http_status", state.LastHttpStatus);
        AddNullable(update, "$error", state.LastError);
        await update.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<Dictionary<(string? Title, string? UpdatedAt), ExistingOutage>> ReadExistingByKeyAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string provider,
        IReadOnlyList<CloudOutageEntry> items,
        CancellationToken cancellationToken)
    {
        var timestamps = items.Select(item => item.UpdatedAt ?? DateTime.UtcNow)
            .Distinct().ToArray();
        if (timestamps.Length == 0) return [];
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var parameters = timestamps.Select((_, index) => $"$date{index}").ToArray();
        command.CommandText = $"""
            SELECT id, title, updated_at, is_resolved, external_id
            FROM cloud_outages
            WHERE provider = $provider AND updated_at IN ({string.Join(", ", parameters)})
            """;
        command.Parameters.AddWithValue("$provider", provider);
        for (var index = 0; index < timestamps.Length; index++)
        {
            command.Parameters.AddWithValue(parameters[index], FormatDate(timestamps[index]));
        }
        var result = new Dictionary<(string? Title, string? UpdatedAt), ExistingOutage>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var existing = ReadExisting(reader);
            result[(existing.Title, FormatDate(existing.UpdatedAt ?? DateTime.MinValue))] = existing;
        }
        return result;
    }

    private static async Task<Dictionary<string, ExistingOutage>> ReadExistingByIdAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string provider,
        IReadOnlyList<CloudOutageEntry> items,
        CancellationToken cancellationToken)
    {
        var ids = items.Select(item => item.ExternalId)
            .Where(id => !string.IsNullOrEmpty(id))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (ids.Length == 0) return new Dictionary<string, ExistingOutage>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var parameters = ids.Select((_, index) => $"$id{index}").ToArray();
        command.CommandText = $"""
            SELECT id, title, updated_at, is_resolved, external_id
            FROM cloud_outages
            WHERE provider = $provider AND external_id IN ({string.Join(", ", parameters)})
            """;
        command.Parameters.AddWithValue("$provider", provider);
        for (var index = 0; index < ids.Length; index++)
        {
            command.Parameters.AddWithValue(parameters[index], ids[index]!);
        }
        var result = new Dictionary<string, ExistingOutage>(StringComparer.Ordinal);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var existing = ReadExisting(reader);
            if (existing.ExternalId is not null) result[existing.ExternalId] = existing;
        }
        return result;
    }

    private static async Task<ExistingOutage?> InsertAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        CloudOutageEntry item,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT OR IGNORE INTO cloud_outages (
                provider, service, title, description, link, is_resolved, updated_at, external_id, status_code
            ) VALUES (
                $provider, $service, $title, $description, $link, $is_resolved, $updated_at, $external_id, $status_code
            )
            """;
        AddOutageParameters(command, item);
        var inserted = await command.ExecuteNonQueryAsync(cancellationToken);
        if (inserted == 0) return null;
        await using var idCommand = connection.CreateCommand();
        idCommand.Transaction = transaction;
        idCommand.CommandText = "SELECT last_insert_rowid()";
        var id = Convert.ToInt32(await idCommand.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
        return ToExisting(id, item);
    }

    private static async Task UpdateMicrosoft365Async(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int id,
        CloudOutageEntry item,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE cloud_outages
            SET service = $service, title = $title, description = $description, link = $link,
                is_resolved = $is_resolved, updated_at = $updated_at, status_code = $status_code
            WHERE id = $id
            """;
        AddOutageParameters(command, item);
        command.Parameters.AddWithValue("$id", id);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task MarkResolvedAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        int id,
        DateTime updatedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "UPDATE cloud_outages SET is_resolved = 1, updated_at = $updated_at WHERE id = $id";
        command.Parameters.AddWithValue("$updated_at", FormatDate(updatedAtUtc));
        command.Parameters.AddWithValue("$id", id);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static void AddOutageParameters(SqliteCommand command, CloudOutageEntry item)
    {
        AddNullable(command, "$provider", item.Provider);
        AddNullable(command, "$service", item.Service);
        AddNullable(command, "$title", item.Title);
        AddNullable(command, "$description", item.Description);
        AddNullable(command, "$link", item.Link);
        command.Parameters.AddWithValue("$is_resolved", item.IsResolved == true);
        command.Parameters.AddWithValue("$updated_at", FormatDate(item.UpdatedAt ?? DateTime.UtcNow));
        AddNullable(command, "$external_id", item.ExternalId);
        AddNullable(command, "$status_code", item.StatusCode);
    }

    private static ExistingOutage ToExisting(int id, CloudOutageEntry item) => new(
        id, item.Title, item.UpdatedAt, item.IsResolved, item.ExternalId);

    private static ExistingOutage ReadExisting(SqliteDataReader reader) => new(
        reader.GetInt32(0),
        ReadString(reader, 1),
        ReadDateTime(reader, 2),
        reader.IsDBNull(3) ? false : reader.GetBoolean(3),
        ReadString(reader, 4));

    private static void AddNullableDate(SqliteCommand command, string name, DateTime? value) =>
        command.Parameters.AddWithValue(name, value is { } date ? FormatDate(date) : DBNull.Value);

    private static void AddNullable(SqliteCommand command, string name, object? value) =>
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private sealed record ExistingOutage(
        int Id,
        string? Title,
        DateTime? UpdatedAt,
        bool? IsResolved,
        string? ExternalId);
}
