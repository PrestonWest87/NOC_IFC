using System.Globalization;
using NocIfc.Application.Abstractions.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed record AssetImportResult(bool Success, string Message);

public sealed record HardwareAssetImportRow(IReadOnlyDictionary<string, object> Values);

public sealed class AssetInventoryCommands(IAssetInventoryStore assets)
{
    private static readonly HashSet<string> HardwareColumns = new(
    [
        "id", "ip_address", "asset_name", "host_type", "ip_addresses", "operating_system",
        "os_architecture", "os_family", "os_product", "os_vendor", "os_version", "instances",
        "critical_instances", "severe_instances", "moderate_instances", "vulnerabilities",
        "critical_vulnerabilities", "severe_vulnerabilities", "moderate_vulnerabilities",
        "exploit_count", "malware_count", "raw_risk_score", "risk_score", "last_updated",
    ], StringComparer.Ordinal);

    private static readonly HashSet<string> IntegerColumns = new(
    [
        "id", "instances", "critical_instances", "severe_instances", "moderate_instances",
        "vulnerabilities", "critical_vulnerabilities", "severe_vulnerabilities",
        "moderate_vulnerabilities", "exploit_count", "malware_count",
    ], StringComparer.Ordinal);

    private static readonly HashSet<string> DoubleColumns = new(["raw_risk_score", "risk_score"], StringComparer.Ordinal);

    public async Task<AssetImportResult> ImportSoftwareCsvAsync(string csvText, CancellationToken cancellationToken)
    {
        List<List<string>> rows;
        try
        {
            rows = CsvRecordParser.Read(csvText ?? "");
        }
        catch (ArgumentException exception)
        {
            return new AssetImportResult(false, exception.Message);
        }
        if (rows.Count == 0)
        {
            return new AssetImportResult(false, "CSV must contain a 'name' column.");
        }

        var nameIndex = -1;
        for (var index = 0; index < rows[0].Count; index++)
        {
            if (rows[0][index].Trim().ToLowerInvariant() == "name")
            {
                nameIndex = index;
            }
        }
        if (nameIndex < 0)
        {
            return new AssetImportResult(false, "CSV must contain a 'name' column.");
        }

        var names = new List<string>();
        foreach (var row in rows.Skip(1))
        {
            var name = nameIndex < row.Count ? row[nameIndex].Trim() : "";
            if (name.Length > 0)
            {
                names.Add(name);
            }
        }
        if (names.Count == 0)
        {
            return new AssetImportResult(false, "No valid rows found.");
        }

        await assets.ReplaceSoftwareAssetsAsync(names, cancellationToken);
        return new AssetImportResult(true, $"Imported {names.Count} software assets.");
    }

    public async Task<AssetImportResult> ImportHardwareCsvAsync(string csvText, CancellationToken cancellationToken)
    {
        List<List<string>> rows;
        try
        {
            rows = CsvRecordParser.Read(csvText ?? "");
        }
        catch (ArgumentException exception)
        {
            return new AssetImportResult(false, exception.Message);
        }
        if (rows.Count == 0)
        {
            return new AssetImportResult(false, "CSV must contain an 'IP Address' column.");
        }

        var headerMap = new Dictionary<string, int>(StringComparer.Ordinal);
        for (var index = 0; index < rows[0].Count; index++)
        {
            var normalized = rows[0][index].Trim().ToLowerInvariant().Replace(' ', '_');
            headerMap[normalized] = index;
        }
        if (!headerMap.ContainsKey("ip_address"))
        {
            return new AssetImportResult(false, "CSV must contain an 'IP Address' column.");
        }

        var hardwareRows = new List<HardwareAssetImportRow>();
        for (var rowNumber = 1; rowNumber < rows.Count; rowNumber++)
        {
            var values = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (var (field, column) in headerMap)
            {
                if (!HardwareColumns.Contains(field) || column >= rows[rowNumber].Count)
                {
                    continue;
                }
                var raw = rows[rowNumber][column].Trim();
                if (raw.Length == 0)
                {
                    continue;
                }
                try
                {
                    values[field] = ParseHardwareValue(field, raw);
                }
                catch (ArgumentException exception)
                {
                    return new AssetImportResult(false, $"CSV row {rowNumber + 1}: {exception.Message}");
                }
            }
            if (values.TryGetValue("ip_address", out var address) && address is string text && text.Length > 0)
            {
                hardwareRows.Add(new HardwareAssetImportRow(values));
            }
        }
        if (hardwareRows.Count == 0)
        {
            return new AssetImportResult(false, "No valid rows found.");
        }

        await assets.ReplaceHardwareAssetsAsync(hardwareRows, cancellationToken);
        return new AssetImportResult(true, $"Imported {hardwareRows.Count} hardware assets.");
    }

    private static object ParseHardwareValue(string field, string raw)
    {
        if (IntegerColumns.Contains(field))
        {
            return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var integer)
                ? integer
                : throw new ArgumentException($"{field} must be an integer.");
        }
        if (DoubleColumns.Contains(field))
        {
            return double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var number)
                && double.IsFinite(number)
                    ? number
                    : throw new ArgumentException($"{field} must be a number.");
        }
        if (field == "last_updated")
        {
            return DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date)
                ? DateTime.SpecifyKind(date, DateTimeKind.Unspecified)
                : throw new ArgumentException("last_updated must be a valid date and time.");
        }
        return raw;
    }
}
