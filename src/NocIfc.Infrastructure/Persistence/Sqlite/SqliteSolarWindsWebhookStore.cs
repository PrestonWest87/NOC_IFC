using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Domain.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteSolarWindsWebhookStore(SqliteConnectionFactory connections) : ISolarWindsWebhookStore
{
    public async Task PersistAsync(
        SolarWindsWebhookEvent webhookEvent,
        string rawPayloadJson,
        DateTime receivedAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var timestamp = FormatDate(receivedAtUtc);
        if (webhookEvent.IsResolution)
        {
            var site = string.IsNullOrWhiteSpace(webhookEvent.SiteName)
                || string.Equals(webhookEvent.SiteName.Trim(), "Unknown", StringComparison.OrdinalIgnoreCase)
                ? null
                : webhookEvent.SiteName;
            await using var resolve = connection.CreateCommand();
            resolve.Transaction = transaction;
            resolve.CommandText = """
                UPDATE solarwinds_alerts
                SET status = 'Resolved', resolved_at = $now
                WHERE node_name = $node AND status != 'Resolved'
                  AND ($site IS NULL OR mapped_location = $site)
                """;
            resolve.Parameters.AddWithValue("$now", timestamp);
            resolve.Parameters.AddWithValue("$node", webhookEvent.NodeName);
            resolve.Parameters.AddWithValue("$site", (object?)site ?? DBNull.Value);
            await resolve.ExecuteNonQueryAsync(cancellationToken);
            await InsertTimelineAsync(connection, transaction, timestamp, "Resolution",
                $"{webhookEvent.NodeName} recovered at {webhookEvent.SiteName}", webhookEvent.SiteName,
                cancellationToken);
        }
        else
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO solarwinds_alerts
                    (event_type, severity, node_name, ip_address, status, details, raw_payload,
                     mapped_location, received_at, is_dispatched, is_ticketed, is_correlated,
                     needs_dispatch, device_type, event_category)
                VALUES
                    ($event_type, $severity, $node_name, $ip_address, $status, $details, $raw_payload,
                     $site, $received_at, 0, 0, 0, 0, $device_type, 'General Degradation')
                """;
            insert.Parameters.AddWithValue("$event_type", webhookEvent.EventType);
            insert.Parameters.AddWithValue("$severity", webhookEvent.Severity);
            insert.Parameters.AddWithValue("$node_name", webhookEvent.NodeName);
            insert.Parameters.AddWithValue("$ip_address", webhookEvent.IpAddress);
            insert.Parameters.AddWithValue("$status", webhookEvent.Status);
            insert.Parameters.AddWithValue("$details", webhookEvent.Details);
            insert.Parameters.AddWithValue("$raw_payload", rawPayloadJson);
            insert.Parameters.AddWithValue("$site", webhookEvent.SiteName);
            insert.Parameters.AddWithValue("$received_at", timestamp);
            insert.Parameters.AddWithValue("$device_type", webhookEvent.DeviceType);
            await insert.ExecuteNonQueryAsync(cancellationToken);
            await InsertTimelineAsync(connection, transaction, timestamp, "Alert",
                $"[CRITICAL] Alert: {webhookEvent.NodeName} ({webhookEvent.DeviceType}) at {webhookEvent.SiteName}",
                webhookEvent.SiteName, cancellationToken);
        }
        transaction.Commit();
    }

    private static async Task InsertTimelineAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string timestamp,
        string eventType,
        string message,
        string siteName,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO timeline_events (timestamp, source, event_type, message, site_name)
            VALUES ($timestamp, 'Webhook', $event_type, $message, $site)
            """;
        command.Parameters.AddWithValue("$timestamp", timestamp);
        command.Parameters.AddWithValue("$event_type", eventType);
        command.Parameters.AddWithValue("$message", message);
        command.Parameters.AddWithValue("$site", siteName);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
