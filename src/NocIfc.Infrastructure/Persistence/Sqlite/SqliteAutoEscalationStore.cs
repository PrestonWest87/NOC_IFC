using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAutoEscalationStore(SqliteConnectionFactory connections) : IAutoEscalationStore
{
    public async Task<bool> IsNodeOnCooldownAsync(
        int alertId,
        string nodeName,
        string? siteName,
        DateTime cooldownCutoffUtc,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(nodeName)) return false;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT 1
            FROM solarwinds_alerts
            WHERE id != $alert_id
              AND node_name = $node_name
              AND ($site IS NULL OR mapped_location = $site)
              AND ((is_dispatched = 1 AND dispatched_at >= $cutoff)
                OR (is_ticketed = 1 AND received_at >= $cutoff))
            LIMIT 1
            """;
        command.Parameters.AddWithValue("$alert_id", alertId);
        command.Parameters.AddWithValue("$node_name", nodeName);
        command.Parameters.AddWithValue("$site", (object?)siteName ?? DBNull.Value);
        command.Parameters.AddWithValue("$cutoff", FormatDate(cooldownCutoffUtc));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    public async Task<int> MarkTicketedAsync(IReadOnlyList<int> alertIds, CancellationToken cancellationToken)
    {
        var ids = alertIds.Where(id => id > 0).Distinct().ToArray();
        if (ids.Length == 0) return 0;
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var updated = 0;
        foreach (var id in ids)
        {
            await using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "UPDATE solarwinds_alerts SET is_ticketed = 1 WHERE id = $id AND status != 'Resolved'";
            command.Parameters.AddWithValue("$id", id);
            updated += await command.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
        return updated;
    }

    public async Task<bool> IsNodePagedAsync(
        string siteName,
        string? nodeName,
        int alertId,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = string.IsNullOrWhiteSpace(nodeName)
            ? "SELECT 1 FROM solarwinds_alerts WHERE id = $id AND onpage_sent_at IS NOT NULL LIMIT 1"
            : """
              SELECT 1 FROM solarwinds_alerts
              WHERE node_name = $node AND mapped_location = $site
                AND status != 'Resolved' AND onpage_sent_at IS NOT NULL
              LIMIT 1
              """;
        command.Parameters.AddWithValue("$id", alertId);
        command.Parameters.AddWithValue("$node", (object?)nodeName ?? DBNull.Value);
        command.Parameters.AddWithValue("$site", siteName);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }

    public async Task<int> MarkPageSentAsync(
        string siteName,
        string? nodeName,
        int alertId,
        DateTime sentAtUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        var timestamp = FormatDate(sentAtUtc);
        await using var alerts = connection.CreateCommand();
        alerts.Transaction = transaction;
        alerts.CommandText = string.IsNullOrWhiteSpace(nodeName)
            ? "UPDATE solarwinds_alerts SET onpage_sent_at = $now WHERE id = $id AND status != 'Resolved'"
            : "UPDATE solarwinds_alerts SET onpage_sent_at = $now WHERE node_name = $node AND mapped_location = $site AND status != 'Resolved'";
        alerts.Parameters.AddWithValue("$now", timestamp);
        alerts.Parameters.AddWithValue("$id", alertId);
        alerts.Parameters.AddWithValue("$node", (object?)nodeName ?? DBNull.Value);
        alerts.Parameters.AddWithValue("$site", siteName);
        var updated = await alerts.ExecuteNonQueryAsync(cancellationToken);

        await using var location = connection.CreateCommand();
        location.Transaction = transaction;
        location.CommandText = "UPDATE monitored_locations SET last_escalation_ticket = $now WHERE name = $site";
        location.Parameters.AddWithValue("$now", timestamp);
        location.Parameters.AddWithValue("$site", siteName);
        await location.ExecuteNonQueryAsync(cancellationToken);
        transaction.Commit();
        return updated;
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
