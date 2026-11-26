using System.Globalization;
using Microsoft.Data.Sqlite;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed record NwsPollReservation(
    string Status,
    string? Data,
    DateTime? LastAttemptAt,
    DateTime? LastSuccessAt,
    DateTime? RetryAfterAt,
    string? ETag,
    string? LastModified);

public sealed record RegionalHazardSyncRow(
    string HazardId,
    string HazardType,
    string Severity,
    string Title,
    string Description,
    string Location,
    DateTime? SentAt,
    DateTime? EffectiveAt,
    DateTime? OnsetAt,
    DateTime? ExpiresAt,
    DateTime? EventEndingAt,
    string MessageType,
    string ReferencesJson,
    string CoverageScope,
    string CoveragePrecision,
    string Status);

public sealed record RegionalCapReference(string Identifier, string Status);
public sealed record RegionalAlertState(bool Exists, string? AlertedEarthquakeIds, string? AlertedWildfireIds, string? WildfireProximityState);

public sealed class SqliteRegionalHazardSyncStore(SqliteConnectionFactory connections)
{
    private const string NwsFeedName = "nws_region";

    public async Task<NwsPollReservation> ReserveNwsPollAsync(DateTime nowUtc, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using (var ensure = connection.CreateCommand())
        {
            ensure.CommandText = "INSERT INTO geojson_cache(feed_name, data) VALUES ($feed, NULL) ON CONFLICT(feed_name) DO NOTHING";
            ensure.Parameters.AddWithValue("$feed", NwsFeedName);
            await ensure.ExecuteNonQueryAsync(cancellationToken);
        }

        int reserved;
        await using (var update = connection.CreateCommand())
        {
            update.CommandText = """
                UPDATE geojson_cache
                SET last_attempt_at = $now
                WHERE feed_name = $feed
                  AND (last_attempt_at IS NULL OR julianday(last_attempt_at) <= julianday($now, '-60 seconds'))
                  AND (retry_after_at IS NULL OR julianday(retry_after_at) <= julianday($now))
                """;
            update.Parameters.AddWithValue("$now", FormatDate(nowUtc));
            update.Parameters.AddWithValue("$feed", NwsFeedName);
            reserved = await update.ExecuteNonQueryAsync(cancellationToken);
        }

        string? data;
        DateTime? lastAttempt;
        DateTime? lastSuccess;
        DateTime? retryAfter;
        string? etag;
        string? lastModified;
        await using (var read = connection.CreateCommand())
        {
            read.CommandText = """
                SELECT data, last_attempt_at, last_success_at, retry_after_at, etag, last_modified
                FROM geojson_cache WHERE feed_name = $feed
                """;
            read.Parameters.AddWithValue("$feed", NwsFeedName);
            await using var reader = await read.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
            {
                return new NwsPollReservation("error", null, null, null, null, null, null);
            }
            data = ReadString(reader, 0);
            lastAttempt = ReadDateTime(reader, 1);
            lastSuccess = ReadDateTime(reader, 2);
            retryAfter = ReadDateTime(reader, 3);
            etag = ReadString(reader, 4);
            lastModified = ReadString(reader, 5);
        }

        var status = reserved == 1
            ? "reserved"
            : retryAfter is { } retry && retry > nowUtc ? "backoff" : "throttled";
        if (status is "backoff" or "throttled")
        {
            await MarkNwsExpiredAsync(connection, nowUtc, cancellationToken);
        }
        return new NwsPollReservation(status, data, lastAttempt, lastSuccess, retryAfter, etag, lastModified);
    }

    public async Task ClearNwsValidatorsAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE geojson_cache SET etag = NULL, last_modified = NULL WHERE feed_name = $feed";
        command.Parameters.AddWithValue("$feed", NwsFeedName);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task RecordNwsNotModifiedAsync(
        DateTime finishedAtUtc,
        int durationMs,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var update = connection.CreateCommand();
        update.CommandText = """
            UPDATE geojson_cache
            SET last_success_at = $finished, last_error = NULL, retry_after_at = NULL,
                last_http_status = 304, last_duration_ms = $duration
            WHERE feed_name = $feed
            """;
        update.Parameters.AddWithValue("$finished", FormatDate(finishedAtUtc));
        update.Parameters.AddWithValue("$duration", durationMs);
        update.Parameters.AddWithValue("$feed", NwsFeedName);
        await update.ExecuteNonQueryAsync(cancellationToken);
        await using (var seen = connection.CreateCommand())
        {
            seen.CommandText = "UPDATE regional_hazards SET last_seen_at = $now WHERE status = 'active'";
            seen.Parameters.AddWithValue("$now", FormatDate(finishedAtUtc));
            await seen.ExecuteNonQueryAsync(cancellationToken);
        }
        await MarkNwsExpiredAsync(connection, finishedAtUtc, cancellationToken);
    }

    public async Task RecordNwsFailureAsync(
        DateTime attemptedAtUtc,
        int? httpStatus,
        int durationMs,
        string error,
        DateTime? retryAfterAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var update = connection.CreateCommand();
        update.CommandText = """
            UPDATE geojson_cache
            SET last_attempt_at = $attempted, last_error = $error, last_http_status = $status,
                last_duration_ms = $duration, retry_after_at = $retryAfter
            WHERE feed_name = $feed
            """;
        update.Parameters.AddWithValue("$attempted", FormatDate(attemptedAtUtc));
        update.Parameters.AddWithValue("$error", Limit(error, 2000));
        update.Parameters.AddWithValue("$status", (object?)httpStatus ?? DBNull.Value);
        update.Parameters.AddWithValue("$duration", durationMs);
        update.Parameters.AddWithValue("$retryAfter", (object?)(retryAfterAtUtc is { } retry ? FormatDate(retry) : null) ?? DBNull.Value);
        update.Parameters.AddWithValue("$feed", NwsFeedName);
        await update.ExecuteNonQueryAsync(cancellationToken);
        await MarkNwsExpiredAsync(connection, attemptedAtUtc, cancellationToken);
    }

    public async Task SaveNwsSnapshotAsync(
        string sourceJson,
        string arkansasJson,
        string borderJson,
        string coverageSummaryJson,
        int sourceFeatureCount,
        int arkansasFeatureCount,
        int borderFeatureCount,
        string? etag,
        string? lastModified,
        DateTime finishedAtUtc,
        int durationMs,
        IReadOnlyList<RegionalHazardSyncRow> incoming,
        IReadOnlyList<RegionalCapReference> references,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var source = connection.CreateCommand())
        {
            source.Transaction = transaction;
            source.CommandText = """
                INSERT INTO geojson_cache(
                    feed_name, data, updated_at, last_attempt_at, last_success_at, last_error,
                    last_http_status, last_duration_ms, retry_after_at, etag, last_modified,
                    feature_count, coverage_summary)
                VALUES ($feed, $data, $now, $now, $now, NULL, 200, $duration, NULL,
                        $etag, $lastModified, $count, $coverage)
                ON CONFLICT(feed_name) DO UPDATE SET
                    data = excluded.data, updated_at = excluded.updated_at,
                    last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at,
                    last_error = NULL, last_http_status = 200, last_duration_ms = excluded.last_duration_ms,
                    retry_after_at = NULL, etag = COALESCE(excluded.etag, geojson_cache.etag),
                    last_modified = COALESCE(excluded.last_modified, geojson_cache.last_modified),
                    feature_count = excluded.feature_count, coverage_summary = excluded.coverage_summary
                """;
            source.Parameters.AddWithValue("$feed", NwsFeedName);
            source.Parameters.AddWithValue("$data", sourceJson);
            source.Parameters.AddWithValue("$now", FormatDate(finishedAtUtc));
            source.Parameters.AddWithValue("$duration", durationMs);
            source.Parameters.AddWithValue("$etag", (object?)etag ?? DBNull.Value);
            source.Parameters.AddWithValue("$lastModified", (object?)lastModified ?? DBNull.Value);
            source.Parameters.AddWithValue("$count", sourceFeatureCount);
            source.Parameters.AddWithValue("$coverage", coverageSummaryJson);
            await source.ExecuteNonQueryAsync(cancellationToken);
        }

        await UpsertLayerAsync(connection, transaction, "nws_ar", arkansasJson, arkansasFeatureCount, finishedAtUtc, cancellationToken);
        await UpsertLayerAsync(connection, transaction, "nws_oos", borderJson, borderFeatureCount, finishedAtUtc, cancellationToken);
        await MarkNwsExpiredAsync(connection, finishedAtUtc, cancellationToken, transaction);
        await ReconcileNwsAlertsAsync(connection, transaction, incoming, references, finishedAtUtc, cancellationToken);
        await MarkNwsExpiredAsync(connection, finishedAtUtc, cancellationToken, transaction);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task SaveGeoJsonFeedAsync(
        string feedName,
        string dataJson,
        int featureCount,
        int durationMs,
        DateTime finishedAtUtc,
        string? coverageSummaryJson,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO geojson_cache(
                feed_name, data, updated_at, last_attempt_at, last_success_at, last_error,
                last_http_status, last_duration_ms, retry_after_at, feature_count, coverage_summary)
            VALUES ($feed, $data, $now, $now, $now, NULL, 200, $duration, NULL, $count, $coverage)
            ON CONFLICT(feed_name) DO UPDATE SET
                data = excluded.data, updated_at = excluded.updated_at,
                last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at,
                last_error = NULL, last_http_status = 200, last_duration_ms = excluded.last_duration_ms,
                retry_after_at = NULL, feature_count = excluded.feature_count,
                coverage_summary = excluded.coverage_summary
            """;
        command.Parameters.AddWithValue("$feed", feedName);
        command.Parameters.AddWithValue("$data", dataJson);
        command.Parameters.AddWithValue("$now", FormatDate(finishedAtUtc));
        command.Parameters.AddWithValue("$duration", durationMs);
        command.Parameters.AddWithValue("$count", featureCount);
        command.Parameters.AddWithValue("$coverage", (object?)coverageSummaryJson ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task RecordGeoJsonFailureAsync(
        string feedName,
        string error,
        int? httpStatus,
        int durationMs,
        DateTime attemptedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO geojson_cache(feed_name, data, last_attempt_at, last_error, last_http_status, last_duration_ms)
            VALUES ($feed, NULL, $attempted, $error, $status, $duration)
            ON CONFLICT(feed_name) DO UPDATE SET
                last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error,
                last_http_status = excluded.last_http_status, last_duration_ms = excluded.last_duration_ms
            """;
        command.Parameters.AddWithValue("$feed", feedName);
        command.Parameters.AddWithValue("$attempted", FormatDate(attemptedAtUtc));
        command.Parameters.AddWithValue("$error", Limit(error, 2000));
        command.Parameters.AddWithValue("$status", (object?)httpStatus ?? DBNull.Value);
        command.Parameters.AddWithValue("$duration", durationMs);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<RegionalAlertState> GetAlertStateAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT alerted_eq_ids, alerted_wildfire_ids, wildfire_proximity_state FROM system_config ORDER BY id LIMIT 1";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new RegionalAlertState(false, null, null, null);
        }
        return new RegionalAlertState(true, ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2));
    }

    public async Task SaveEarthquakeAlertIdsAsync(string idsJson, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE system_config SET alerted_eq_ids = $ids WHERE id = (SELECT id FROM system_config ORDER BY id LIMIT 1)";
        command.Parameters.AddWithValue("$ids", idsJson);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task SaveWildfireAlertStateAsync(
        string alertedIdsJson,
        string proximityStateJson,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE system_config SET alerted_wildfire_ids = $ids, wildfire_proximity_state = $state
            WHERE id = (SELECT id FROM system_config ORDER BY id LIMIT 1)
            """;
        command.Parameters.AddWithValue("$ids", alertedIdsJson);
        command.Parameters.AddWithValue("$state", proximityStateJson);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task UpsertLayerAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string feedName,
        string dataJson,
        int featureCount,
        DateTime finishedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO geojson_cache(
                feed_name, data, updated_at, last_attempt_at, last_success_at, last_error,
                last_http_status, feature_count)
            VALUES ($feed, $data, $now, $now, $now, NULL, 200, $count)
            ON CONFLICT(feed_name) DO UPDATE SET
                data = excluded.data, updated_at = excluded.updated_at,
                last_attempt_at = excluded.last_attempt_at, last_success_at = excluded.last_success_at,
                last_error = NULL, last_http_status = 200, feature_count = excluded.feature_count
            """;
        command.Parameters.AddWithValue("$feed", feedName);
        command.Parameters.AddWithValue("$data", dataJson);
        command.Parameters.AddWithValue("$now", FormatDate(finishedAtUtc));
        command.Parameters.AddWithValue("$count", featureCount);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task ReconcileNwsAlertsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        IReadOnlyList<RegionalHazardSyncRow> incoming,
        IReadOnlyList<RegionalCapReference> references,
        DateTime nowUtc,
        CancellationToken cancellationToken)
    {
        var activeIds = new HashSet<string>(StringComparer.Ordinal);
        await using (var query = connection.CreateCommand())
        {
            query.Transaction = transaction;
            query.CommandText = "SELECT hazard_id FROM regional_hazards WHERE status = 'active'";
            await using var reader = await query.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                if (!reader.IsDBNull(0)) activeIds.Add(reader.GetString(0));
            }
        }

        foreach (var reference in references)
        {
            foreach (var activeId in activeIds.ToArray())
            {
                if (ReferenceMatches(activeId, reference.Identifier))
                {
                    await using var update = connection.CreateCommand();
                    update.Transaction = transaction;
                    update.CommandText = "UPDATE regional_hazards SET status = $status, updated_at = $now WHERE hazard_id = $id AND status = 'active'";
                    update.Parameters.AddWithValue("$status", reference.Status);
                    update.Parameters.AddWithValue("$now", FormatDate(nowUtc));
                    update.Parameters.AddWithValue("$id", activeId);
                    await update.ExecuteNonQueryAsync(cancellationToken);
                    activeIds.Remove(activeId);
                }
            }
        }

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var hazard in incoming)
        {
            await using var upsert = connection.CreateCommand();
            upsert.Transaction = transaction;
            upsert.CommandText = """
                INSERT INTO regional_hazards(
                    hazard_id, hazard_type, severity, title, description, location, updated_at,
                    last_seen_at, status, sent_at, effective_at, onset_at, expires_at,
                    event_ending_at, message_type, references_json, coverage_scope, coverage_precision)
                VALUES ($id, $type, $severity, $title, $description, $location, $now,
                        $now, $status, $sent, $effective, $onset, $expires, $ending,
                        $messageType, $references, $scope, $precision)
                ON CONFLICT(hazard_id) DO UPDATE SET
                    hazard_type = excluded.hazard_type, severity = excluded.severity,
                    title = excluded.title, description = excluded.description, location = excluded.location,
                    updated_at = excluded.updated_at, last_seen_at = excluded.last_seen_at,
                    status = excluded.status, sent_at = excluded.sent_at, effective_at = excluded.effective_at,
                    onset_at = excluded.onset_at, expires_at = excluded.expires_at,
                    event_ending_at = excluded.event_ending_at, message_type = excluded.message_type,
                    references_json = excluded.references_json, coverage_scope = excluded.coverage_scope,
                    coverage_precision = excluded.coverage_precision
                """;
            Add(upsert, "$id", hazard.HazardId);
            Add(upsert, "$type", hazard.HazardType);
            Add(upsert, "$severity", hazard.Severity);
            Add(upsert, "$title", hazard.Title);
            Add(upsert, "$description", hazard.Description);
            Add(upsert, "$location", hazard.Location);
            Add(upsert, "$now", FormatDate(nowUtc));
            Add(upsert, "$status", hazard.Status);
            Add(upsert, "$sent", FormatDate(hazard.SentAt));
            Add(upsert, "$effective", FormatDate(hazard.EffectiveAt));
            Add(upsert, "$onset", FormatDate(hazard.OnsetAt));
            Add(upsert, "$expires", FormatDate(hazard.ExpiresAt));
            Add(upsert, "$ending", FormatDate(hazard.EventEndingAt));
            Add(upsert, "$messageType", hazard.MessageType);
            Add(upsert, "$references", hazard.ReferencesJson);
            Add(upsert, "$scope", hazard.CoverageScope);
            Add(upsert, "$precision", hazard.CoveragePrecision);
            await upsert.ExecuteNonQueryAsync(cancellationToken);
            if (hazard.Status == "active") seenIds.Add(hazard.HazardId);
        }

        foreach (var activeId in activeIds.Except(seenIds, StringComparer.Ordinal))
        {
            await using var deactivate = connection.CreateCommand();
            deactivate.Transaction = transaction;
            deactivate.CommandText = "UPDATE regional_hazards SET status = 'inactive', updated_at = $now WHERE hazard_id = $id AND status = 'active'";
            deactivate.Parameters.AddWithValue("$now", FormatDate(nowUtc));
            deactivate.Parameters.AddWithValue("$id", activeId);
            await deactivate.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static async Task MarkNwsExpiredAsync(
        SqliteConnection connection,
        DateTime nowUtc,
        CancellationToken cancellationToken,
        SqliteTransaction? transaction = null)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE regional_hazards SET status = 'expired', updated_at = $now
            WHERE status = 'active' AND expires_at IS NOT NULL AND julianday(expires_at) <= julianday($now)
            """;
        command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static bool ReferenceMatches(string hazardId, string referenceId)
    {
        var stored = hazardId.TrimEnd('/');
        var reference = referenceId.TrimEnd('/');
        return stored.Length > 0 && reference.Length > 0
            && (stored == reference || stored.EndsWith('/' + reference, StringComparison.Ordinal)
                || reference.EndsWith('/' + stored, StringComparison.Ordinal));
    }

    private static void Add(SqliteCommand command, string name, string? value) =>
        command.Parameters.AddWithValue(name, (object?)value ?? DBNull.Value);

    private static string? FormatDate(DateTime? value) =>
        value?.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string Limit(string value, int maximum) => value.Length <= maximum ? value : value[..maximum];
}
