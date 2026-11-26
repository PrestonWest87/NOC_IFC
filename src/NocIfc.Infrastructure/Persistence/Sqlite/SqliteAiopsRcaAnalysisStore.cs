using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Domain.AIOps;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAiopsRcaAnalysisStore(SqliteConnectionFactory connections) : IAiopsRcaAnalysisStore
{
    public async Task<AiopsRcaAnalysisContext> GetAnalysisContextAsync(
        DateTime nowUtc,
        DateTime historyCutoffUtc,
        bool includeHistory,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);

        var cloudOutages = new List<AiopsCloudOutageEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT provider FROM cloud_outages WHERE is_resolved = 0 ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                cloudOutages.Add(new AiopsCloudOutageEntry(ReadString(reader, 0)));
            }
        }

        var activeWeather = new List<AiopsWeatherHazardEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT hazard_type, location
                FROM regional_hazards
                WHERE status = 'active'
                  AND (expires_at IS NULL OR julianday(expires_at) > julianday($now))
                  AND (effective_at IS NULL OR julianday(effective_at) <= julianday($now))
                ORDER BY id
                """;
            command.Parameters.AddWithValue("$now", FormatDate(nowUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                activeWeather.Add(new AiopsWeatherHazardEntry(ReadString(reader, 0), ReadString(reader, 1)));
            }
        }

        var activeBgp = new List<AiopsBgpAnomalyEntry>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT asn FROM bgp_anomalies WHERE is_resolved = 0 ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                activeBgp.Add(new AiopsBgpAnomalyEntry(ReadString(reader, 0)));
            }
        }

        var recentAlerts = new List<AiopsHistoricalAlertEntry>();
        if (includeHistory)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT node_name, device_type, mapped_location, raw_payload, status
                FROM solarwinds_alerts
                WHERE received_at >= $cutoff
                ORDER BY id
                """;
            command.Parameters.AddWithValue("$cutoff", FormatDate(historyCutoffUtc));
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                recentAlerts.Add(new AiopsHistoricalAlertEntry(
                    ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2),
                    ReadString(reader, 3), ReadString(reader, 4)));
            }
        }

        return new AiopsRcaAnalysisContext(cloudOutages, activeWeather, activeBgp, recentAlerts);
    }

    private static string FormatDate(DateTime value) =>
        DateTime.SpecifyKind(value, DateTimeKind.Unspecified)
            .ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
}
