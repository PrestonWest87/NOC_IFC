using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteInternalRiskStore(SqliteConnectionFactory connections) : IInternalRiskStore
{
    public async Task<InternalRiskAssetInventory> GetAssetInventoryAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        var hardware = new List<InternalRiskHardwareAsset>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT ip_address, asset_name, operating_system, os_product, os_vendor, os_version FROM hardware_assets ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                hardware.Add(new InternalRiskHardwareAsset(
                    ReadString(reader, 0), ReadString(reader, 1), ReadString(reader, 2),
                    ReadString(reader, 3), ReadString(reader, 4), ReadString(reader, 5)));
            }
        }

        var software = new List<InternalRiskSoftwareAsset>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM software_assets ORDER BY id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                software.Add(new InternalRiskSoftwareAsset(ReadString(reader, 0)));
            }
        }
        return new InternalRiskAssetInventory(hardware, software);
    }

    public async Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        InternalRiskSnapshotEntry? snapshot = null;
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT id, timestamp, score, risk_level, total_assets, total_osint_hits,
                       critical_osint_hits, hw_data_json, sw_data_json
                FROM internal_risk_snapshots
                ORDER BY timestamp DESC
                LIMIT 1
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                snapshot = new InternalRiskSnapshotEntry(
                    reader.GetInt32(0),
                    ReadDateTime(reader, 1),
                    reader.IsDBNull(2) ? null : reader.GetDouble(2),
                    ReadString(reader, 3),
                    reader.IsDBNull(4) ? null : reader.GetInt32(4),
                    reader.IsDBNull(5) ? null : reader.GetInt32(5),
                    reader.IsDBNull(6) ? null : reader.GetInt32(6),
                    ReadJsonArray(reader, 7),
                    ReadJsonArray(reader, 8),
                    "auto");
            }
        }
        if (snapshot is null)
        {
            return null;
        }

        await using (var config = connection.CreateCommand())
        {
            config.CommandText = "SELECT scoring_mode FROM system_config ORDER BY id LIMIT 1";
            var scoringMode = await config.ExecuteScalarAsync(cancellationToken);
            if (scoringMode is string value && !string.IsNullOrEmpty(value))
            {
                snapshot = snapshot with { ScoringMode = value };
            }
        }
        return snapshot;
    }

    public async Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(
        DateTime sinceUtc,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT timestamp, score, risk_level
            FROM internal_risk_snapshots
            WHERE timestamp >= $since
            ORDER BY timestamp ASC
            """;
        command.Parameters.AddWithValue("$since", sinceUtc.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var snapshots = new List<InternalRiskHistoryPoint>();
        while (await reader.ReadAsync(cancellationToken))
        {
            snapshots.Add(new InternalRiskHistoryPoint(
                ReadDateTime(reader, 0),
                reader.IsDBNull(1) ? null : reader.GetDouble(1),
                ReadString(reader, 2)));
        }
        return snapshots;
    }

    public async Task SaveSnapshotAsync(InternalRiskSnapshotEntry snapshot, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = """
                INSERT INTO internal_risk_snapshots (
                    timestamp, score, risk_level, total_assets, total_osint_hits,
                    critical_osint_hits, hw_data_json, sw_data_json
                ) VALUES (
                    $timestamp, $score, $risk_level, $total_assets, $total_osint_hits,
                    $critical_osint_hits, $hw_data, $sw_data
                )
                """;
            insert.Parameters.AddWithValue("$timestamp", FormatDate(snapshot.Timestamp ?? DateTime.UtcNow));
            insert.Parameters.AddWithValue("$score", (object?)snapshot.Score ?? DBNull.Value);
            insert.Parameters.AddWithValue("$risk_level", (object?)snapshot.RiskLevel ?? DBNull.Value);
            insert.Parameters.AddWithValue("$total_assets", (object?)snapshot.TotalAssets ?? DBNull.Value);
            insert.Parameters.AddWithValue("$total_osint_hits", (object?)snapshot.TotalOsintHits ?? DBNull.Value);
            insert.Parameters.AddWithValue("$critical_osint_hits", (object?)snapshot.CriticalOsintHits ?? DBNull.Value);
            insert.Parameters.AddWithValue("$hw_data", snapshot.HardwareData.GetRawText());
            insert.Parameters.AddWithValue("$sw_data", snapshot.SoftwareData.GetRawText());
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        await using (var mirror = connection.CreateCommand())
        {
            mirror.Transaction = transaction;
            mirror.CommandText = "UPDATE system_config SET last_internal_risk = $risk WHERE id = (SELECT id FROM system_config ORDER BY id LIMIT 1)";
            mirror.Parameters.AddWithValue("$risk", (object?)snapshot.RiskLevel ?? DBNull.Value);
            await mirror.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static JsonElement ReadJsonArray(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            using var empty = JsonDocument.Parse("[]");
            return empty.RootElement.Clone();
        }
        using var document = JsonDocument.Parse(reader.GetString(ordinal));
        return document.RootElement.Clone();
    }

    private static string? ReadString(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    private static DateTime? ReadDateTime(SqliteDataReader reader, int ordinal)
    {
        if (reader.IsDBNull(ordinal))
        {
            return null;
        }
        return DateTime.SpecifyKind(reader.GetDateTime(ordinal), DateTimeKind.Unspecified);
    }
}
