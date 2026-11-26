using System.Globalization;
using Microsoft.Data.Sqlite;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Infrastructure.Persistence.Sqlite;

public sealed class SqliteAssetInventoryStore(SqliteConnectionFactory connections) : IAssetInventoryStore
{
    private static readonly string[] HardwareColumns =
    [
        "ip_address", "asset_name", "host_type", "ip_addresses", "operating_system",
        "os_architecture", "os_family", "os_product", "os_vendor", "os_version", "instances",
        "critical_instances", "severe_instances", "moderate_instances", "vulnerabilities",
        "critical_vulnerabilities", "severe_vulnerabilities", "moderate_vulnerabilities",
        "exploit_count", "malware_count", "raw_risk_score", "risk_score", "last_updated",
    ];

    private static readonly string[] IntegerDefaults =
    [
        "instances", "critical_instances", "severe_instances", "moderate_instances", "vulnerabilities",
        "critical_vulnerabilities", "severe_vulnerabilities", "moderate_vulnerabilities", "exploit_count", "malware_count",
    ];

    public async Task ReplaceSoftwareAssetsAsync(IReadOnlyList<string> names, CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM software_assets";
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var name in names)
        {
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO software_assets (name, last_updated) VALUES ($name, $last_updated)";
            insert.Parameters.AddWithValue("$name", name);
            insert.Parameters.AddWithValue("$last_updated", FormatDate(DateTime.UtcNow));
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    public async Task ReplaceHardwareAssetsAsync(
        IReadOnlyList<HardwareAssetImportRow> assets,
        CancellationToken cancellationToken)
    {
        await using var connection = connections.Create();
        await connection.OpenAsync(cancellationToken);
        using var transaction = connection.BeginTransaction();
        await using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM hardware_assets";
            await delete.ExecuteNonQueryAsync(cancellationToken);
        }
        foreach (var asset in assets)
        {
            var values = new Dictionary<string, object>(asset.Values, StringComparer.Ordinal);
            foreach (var field in IntegerDefaults)
            {
                values.TryAdd(field, 0);
            }
            values.TryAdd("raw_risk_score", 0d);
            values.TryAdd("risk_score", 0d);
            values.TryAdd("last_updated", DateTime.UtcNow);

            var fields = HardwareColumns.Where(values.ContainsKey).ToList();
            if (values.TryGetValue("id", out var id))
            {
                fields.Insert(0, "id");
            }
            await using var insert = connection.CreateCommand();
            insert.Transaction = transaction;
            var columnSql = string.Join(", ", fields);
            var parameterSql = string.Join(", ", fields.Select(field => $"${field}"));
            insert.CommandText = $"INSERT INTO hardware_assets ({columnSql}) VALUES ({parameterSql})";
            foreach (var field in fields)
            {
                insert.Parameters.AddWithValue($"${field}", values[field]);
            }
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }
        transaction.Commit();
    }

    private static string FormatDate(DateTime value) =>
        value.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}
