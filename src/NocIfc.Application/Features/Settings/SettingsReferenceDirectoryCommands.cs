using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed record FiberEmailContactInput(string? Name, string? Company, string? Email, string? Phone);
public sealed record OnpageEmailContactInput(string? Department, string? Email);
public sealed record NetworkOrderCircuitInput(
    string? ALocation,
    string? ZLocation,
    string? CircuitNetworkOrderId,
    string? Company,
    IReadOnlyList<string>? AssociatedCircuitNetworkOrderIds);

public sealed record SettingsDirectoryImportResult<T>(
    string Mode,
    int ImportedRows,
    int Added,
    int Updated,
    IReadOnlyList<T> Rows);

public sealed class SettingsReferenceDirectoryCommands(ISettingsReferenceDirectoryStore directories)
{
    private const int MaxRows = 250;
    private const int MaxCsvCharacters = 1_000_000;
    private static readonly Regex CsvHeaderPattern = new("[^a-z0-9]+", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly IReadOnlyDictionary<string, string> FiberCsvAliases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["name"] = "name", ["company"] = "company", ["email"] = "email", ["phone"] = "phone",
    };
    private static readonly IReadOnlyDictionary<string, string> OnpageCsvAliases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["department"] = "department", ["email"] = "email",
    };
    private static readonly IReadOnlyDictionary<string, string> NetworkCsvAliases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["a_location"] = "a_location",
        ["z_location"] = "z_location",
        ["circuit_network_order_id"] = "circuit_network_order_id",
        ["circuit_id"] = "circuit_network_order_id",
        ["network_order_id"] = "circuit_network_order_id",
        ["company"] = "company",
        ["associated_circuit_network_order_ids"] = "associated_circuit_network_order_ids",
        ["associated_circuit_network_order_id"] = "associated_circuit_network_order_ids",
        ["associated_network_order_circuit_ids"] = "associated_circuit_network_order_ids",
        ["associated_network_order_circuit_id"] = "associated_circuit_network_order_ids",
        ["associated_network_order_ids"] = "associated_circuit_network_order_ids",
        ["associated_circuit_ids"] = "associated_circuit_network_order_ids",
    };

    public Task<IReadOnlyList<FiberEmailContactEntry>> GetFiberAsync(CancellationToken cancellationToken) =>
        directories.GetFiberAsync(cancellationToken);

    public Task<IReadOnlyList<OnpageEmailContactEntry>> GetOnpageAsync(CancellationToken cancellationToken) =>
        directories.GetOnpageAsync(cancellationToken);

    public Task<IReadOnlyList<NetworkOrderCircuitEntry>> GetNetworkOrdersAsync(CancellationToken cancellationToken) =>
        directories.GetNetworkOrdersAsync(cancellationToken);

    public Task<IReadOnlyList<FiberEmailContactEntry>> ReplaceFiberAsync(
        IReadOnlyList<FiberEmailContactInput> contacts,
        int actorUserId,
        CancellationToken cancellationToken) =>
        directories.ReplaceFiberAsync(NormalizeFiberContacts(contacts), actorUserId, cancellationToken);

    public Task<IReadOnlyList<OnpageEmailContactEntry>> ReplaceOnpageAsync(
        IReadOnlyList<OnpageEmailContactInput> contacts,
        int actorUserId,
        CancellationToken cancellationToken) =>
        directories.ReplaceOnpageAsync(NormalizeOnpageContacts(contacts), actorUserId, cancellationToken);

    public Task<IReadOnlyList<NetworkOrderCircuitEntry>> ReplaceNetworkOrdersAsync(
        IReadOnlyList<NetworkOrderCircuitInput> records,
        int actorUserId,
        CancellationToken cancellationToken) =>
        directories.ReplaceNetworkOrdersAsync(NormalizeNetworkOrders(records), actorUserId, cancellationToken);

    public async Task<SettingsDirectoryImportResult<FiberEmailContactEntry>> ImportFiberAsync(
        string csvText,
        string mode,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        ValidateImportMode(mode);
        var (incoming, provided) = ParseCsv(
            csvText,
            "Fiber contacts",
            FiberCsvAliases,
            ["name", "company", "email"],
            row => NormalizeFiber(new FiberEmailContactInput(
                Get(row, "name"), Get(row, "company"), Get(row, "email"), Get(row, "phone"))));
        var (rows, added, updated) = mode == "replace"
            ? (incoming, incoming.Count, 0)
            : Merge(
                (await directories.GetFiberAsync(cancellationToken)).Select(ToValue).ToList(),
                incoming,
                row => row.Email,
                (fresh, existing) => provided.Contains("phone") ? fresh : fresh with { Phone = existing.Phone });
        var saved = await directories.ReplaceFiberAsync(rows, actorUserId, cancellationToken);
        return new SettingsDirectoryImportResult<FiberEmailContactEntry>(mode, incoming.Count, added, updated, saved);
    }

    public async Task<SettingsDirectoryImportResult<OnpageEmailContactEntry>> ImportOnpageAsync(
        string csvText,
        string mode,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        ValidateImportMode(mode);
        var (incoming, _) = ParseCsv(
            csvText,
            "ONPAGE contacts",
            OnpageCsvAliases,
            ["department", "email"],
            row => NormalizeOnpage(new OnpageEmailContactInput(Get(row, "department"), Get(row, "email"))));
        var (rows, added, updated) = mode == "replace"
            ? (incoming, incoming.Count, 0)
            : Merge(
                (await directories.GetOnpageAsync(cancellationToken)).Select(ToValue).ToList(),
                incoming,
                row => row.Department,
                (fresh, _) => fresh);
        var saved = await directories.ReplaceOnpageAsync(rows, actorUserId, cancellationToken);
        return new SettingsDirectoryImportResult<OnpageEmailContactEntry>(mode, incoming.Count, added, updated, saved);
    }

    public async Task<SettingsDirectoryImportResult<NetworkOrderCircuitEntry>> ImportNetworkOrdersAsync(
        string csvText,
        string mode,
        int actorUserId,
        CancellationToken cancellationToken)
    {
        ValidateImportMode(mode);
        var (incoming, provided) = ParseCsv(
            csvText,
            "Network orders and circuits",
            NetworkCsvAliases,
            ["a_location", "z_location", "circuit_network_order_id", "company"],
            row => NormalizeNetwork(new NetworkOrderCircuitInput(
                Get(row, "a_location"),
                Get(row, "z_location"),
                Get(row, "circuit_network_order_id"),
                Get(row, "company"),
                ParseAssociatedCsvIds(Get(row, "associated_circuit_network_order_ids")))));
        List<NetworkOrderCircuitValue> rows;
        int added;
        int updated;
        if (mode == "replace")
        {
            rows = incoming;
            added = incoming.Count;
            updated = 0;
        }
        else
        {
            var existing = (await directories.GetNetworkOrdersAsync(cancellationToken)).Select(ToValue).ToList();
            (rows, added, updated) = Merge(
                existing,
                incoming,
                row => row.CircuitNetworkOrderId,
                (fresh, old) => provided.Contains("associated_circuit_network_order_ids")
                    ? fresh
                    : fresh with { AssociatedCircuitNetworkOrderIds = old.AssociatedCircuitNetworkOrderIds });
            if (provided.Contains("associated_circuit_network_order_ids"))
            {
                ClearStaleImportedAssociations(rows, incoming);
            }
        }

        var saved = await directories.ReplaceNetworkOrdersAsync(
            NormalizeNetworkOrders(rows.Select(ToInput).ToList()),
            actorUserId,
            cancellationToken);
        return new SettingsDirectoryImportResult<NetworkOrderCircuitEntry>(mode, incoming.Count, added, updated, saved);
    }

    private static List<FiberEmailContactValue> NormalizeFiberContacts(IReadOnlyList<FiberEmailContactInput> contacts)
    {
        ValidateRows(contacts.Count, "Fiber contacts");
        return contacts.Select(NormalizeFiber).ToList();
    }

    private static List<OnpageEmailContactValue> NormalizeOnpageContacts(IReadOnlyList<OnpageEmailContactInput> contacts)
    {
        ValidateRows(contacts.Count, "ONPAGE contacts");
        return contacts.Select(NormalizeOnpage).ToList();
    }

    private static List<NetworkOrderCircuitValue> NormalizeNetworkOrders(IReadOnlyList<NetworkOrderCircuitInput> records)
    {
        ValidateRows(records.Count, "Network orders and circuits");
        var normalized = records.Select(NormalizeNetwork).ToList();
        var byId = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < normalized.Count; index++)
        {
            var row = normalized[index];
            if (!byId.TryGetValue(row.CircuitNetworkOrderId, out var matches))
            {
                matches = [];
                byId[row.CircuitNetworkOrderId] = matches;
            }
            matches.Add(index);
        }

        for (var rowIndex = 0; rowIndex < normalized.Count; rowIndex++)
        {
            var row = normalized[rowIndex];
            var associations = row.AssociatedCircuitNetworkOrderIds.ToList();
            foreach (var associatedId in row.AssociatedCircuitNetworkOrderIds)
            {
                if (!byId.TryGetValue(associatedId, out var matches))
                {
                    throw new ArgumentException($"Associated circuit '{associatedId}' is not in the Network Orders & Circuits table.");
                }
                if (matches.Count > 1)
                {
                    throw new ArgumentException($"Associated circuit ID '{associatedId}' must identify exactly one table row.");
                }
                var targetIndex = matches[0];
                if (rowIndex == targetIndex)
                {
                    throw new ArgumentException("A circuit cannot be associated with itself.");
                }
                var target = normalized[targetIndex];
                if (!target.AssociatedCircuitNetworkOrderIds.Contains(row.CircuitNetworkOrderId, StringComparer.OrdinalIgnoreCase))
                {
                    normalized[targetIndex] = target with
                    {
                        AssociatedCircuitNetworkOrderIds = target.AssociatedCircuitNetworkOrderIds
                            .Append(row.CircuitNetworkOrderId)
                            .ToArray(),
                    };
                }
            }
            normalized[rowIndex] = row with { AssociatedCircuitNetworkOrderIds = associations };
        }
        return normalized;
    }

    private static FiberEmailContactValue NormalizeFiber(FiberEmailContactInput contact) => new(
        RequiredText(contact.Name, "Name", 128),
        RequiredText(contact.Company, "Company", 200),
        RequiredContactEmail(contact.Email, "Fiber contact"),
        SiteContactRules.NormalizeOptional("phone", contact.Phone));

    private static OnpageEmailContactValue NormalizeOnpage(OnpageEmailContactInput contact) => new(
        RequiredText(contact.Department, "Department", 128),
        RequiredContactEmail(contact.Email, "ONPAGE contact"));

    private static NetworkOrderCircuitValue NormalizeNetwork(NetworkOrderCircuitInput record)
    {
        var inputIds = record.AssociatedCircuitNetworkOrderIds ?? [];
        if (inputIds.Count > MaxRows)
        {
            throw new ArgumentException("A circuit can have at most 250 associated Circuit/Network Order IDs.");
        }
        var ids = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in inputIds)
        {
            var id = RequiredText(value, "Associated Circuit/Network Order ID", 200);
            if (seen.Add(id))
            {
                ids.Add(id);
            }
        }
        return new NetworkOrderCircuitValue(
            RequiredText(record.ALocation, "A location", 250),
            RequiredText(record.ZLocation, "Z location", 250),
            RequiredText(record.CircuitNetworkOrderId, "Circuit/Network Order ID", 200),
            RequiredText(record.Company, "Company", 200),
            ids);
    }

    private static string RequiredContactEmail(string? value, string directory)
    {
        var email = SiteContactRules.NormalizeOptional("email", value);
        return email ?? throw new ArgumentException($"{directory} email is required.");
    }

    private static string RequiredText(string? value, string label, int maximum)
    {
        if (value is null)
        {
            throw new ArgumentException($"{label} must be text.");
        }
        if (value.Any(character => character < ' ' || character == 127))
        {
            throw new ArgumentException($"{label} cannot contain control characters.");
        }
        var normalized = value.Trim();
        if (normalized.Length == 0)
        {
            throw new ArgumentException($"{label} is required.");
        }
        if (normalized.Length > maximum)
        {
            throw new ArgumentException($"{label} must be at most {maximum} characters.");
        }
        return normalized;
    }

    private static void ValidateRows(int count, string label)
    {
        if (count > MaxRows)
        {
            throw new ArgumentException($"{label} can contain at most {MaxRows} rows.");
        }
    }

    private static void ValidateImportMode(string mode)
    {
        if (mode is not ("merge" or "replace"))
        {
            throw new ArgumentException("CSV import mode must be 'merge' or 'replace'.");
        }
    }

    private static (List<T> Rows, HashSet<string> ProvidedFields) ParseCsv<T>(
        string csvText,
        string directory,
        IReadOnlyDictionary<string, string> aliases,
        IReadOnlyCollection<string> requiredFields,
        Func<IReadOnlyDictionary<string, string?>, T> normalizeRow)
    {
        if (string.IsNullOrWhiteSpace(csvText))
        {
            throw new ArgumentException("CSV content is required.");
        }
        if (csvText.Length > MaxCsvCharacters)
        {
            throw new ArgumentException("CSV content must be no more than 1,000,000 characters.");
        }

        var sourceRows = CsvRecordParser.Read(csvText);
        if (sourceRows.Count == 0 || sourceRows[0].Count == 0)
        {
            throw new ArgumentException("CSV must include a header row.");
        }
        var headerMap = new Dictionary<string, int>(StringComparer.Ordinal);
        var unknownHeaders = new List<string>();
        var duplicateHeaders = new List<string>();
        for (var index = 0; index < sourceRows[0].Count; index++)
        {
            var sourceHeader = sourceRows[0][index];
            var normalizedHeader = CsvHeaderPattern.Replace(
                sourceHeader.TrimStart('\ufeff').Trim().ToLowerInvariant(), "_").Trim('_');
            if (!aliases.TryGetValue(normalizedHeader, out var field))
            {
                unknownHeaders.Add(sourceHeader);
            }
            else if (!headerMap.TryAdd(field, index))
            {
                duplicateHeaders.Add(field);
            }
        }
        if (unknownHeaders.Count > 0)
        {
            throw new ArgumentException($"Unsupported {directory} CSV column(s): {string.Join(", ", unknownHeaders)}.");
        }
        if (duplicateHeaders.Count > 0)
        {
            throw new ArgumentException($"CSV contains duplicate columns for: {string.Join(", ", duplicateHeaders.Distinct(StringComparer.Ordinal).OrderBy(field => field, StringComparer.Ordinal))}.");
        }
        var missing = requiredFields.Where(field => !headerMap.ContainsKey(field)).OrderBy(field => field, StringComparer.Ordinal).ToArray();
        if (missing.Length > 0)
        {
            throw new ArgumentException($"{directory} CSV is missing required column(s): {string.Join(", ", missing)}.");
        }

        var providedFields = headerMap.Keys.ToHashSet(StringComparer.Ordinal);
        var records = new List<T>();
        for (var sourceIndex = 1; sourceIndex < sourceRows.Count; sourceIndex++)
        {
            var sourceRow = sourceRows[sourceIndex];
            var rowNumber = sourceIndex + 1;
            if (sourceRow.Count > sourceRows[0].Count)
            {
                throw new ArgumentException($"CSV row {rowNumber} has more values than the header row.");
            }
            var row = headerMap.ToDictionary(
                pair => pair.Key,
                pair => pair.Value < sourceRow.Count ? sourceRow[pair.Value] : null,
                StringComparer.Ordinal);
            if (row.Values.All(value => string.IsNullOrWhiteSpace(value)))
            {
                continue;
            }
            try
            {
                records.Add(normalizeRow(row));
            }
            catch (ArgumentException exception)
            {
                throw new ArgumentException($"CSV row {rowNumber}: {exception.Message}", exception);
            }
            if (records.Count > MaxRows)
            {
                throw new ArgumentException($"{directory} CSV can contain at most {MaxRows} data rows.");
            }
        }
        return (records, providedFields);
    }

    private static (List<T> Rows, int Added, int Updated) Merge<T>(
        IReadOnlyList<T> existing,
        IReadOnlyList<T> incoming,
        Func<T, string> identity,
        Func<T, T, T> updateExisting)
    {
        var merged = existing.ToList();
        var positions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < merged.Count; index++)
        {
            positions[identity(merged[index])] = index;
        }
        var added = 0;
        var updated = 0;
        foreach (var row in incoming)
        {
            var key = identity(row);
            if (positions.TryGetValue(key, out var index))
            {
                merged[index] = updateExisting(row, merged[index]);
                updated++;
            }
            else
            {
                positions[key] = merged.Count;
                merged.Add(row);
                added++;
            }
        }
        return (merged, added, updated);
    }

    private static void ClearStaleImportedAssociations(
        List<NetworkOrderCircuitValue> rows,
        IReadOnlyList<NetworkOrderCircuitValue> incoming)
    {
        var incomingLinks = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in incoming)
        {
            incomingLinks[row.CircuitNetworkOrderId] = row.AssociatedCircuitNetworkOrderIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        foreach (var (sourceId, linkedIds) in incomingLinks)
        {
            for (var index = 0; index < rows.Count; index++)
            {
                var target = rows[index];
                var targetId = target.CircuitNetworkOrderId;
                if (StringComparer.OrdinalIgnoreCase.Equals(targetId, sourceId)
                    || linkedIds.Contains(targetId)
                    || (incomingLinks.TryGetValue(targetId, out var targetLinks) && targetLinks.Contains(sourceId)))
                {
                    continue;
                }
                var remaining = target.AssociatedCircuitNetworkOrderIds
                    .Where(value => !StringComparer.OrdinalIgnoreCase.Equals(value, sourceId))
                    .ToArray();
                if (remaining.Length != target.AssociatedCircuitNetworkOrderIds.Count)
                {
                    rows[index] = target with { AssociatedCircuitNetworkOrderIds = remaining };
                }
            }
        }
    }

    private static string? Get(IReadOnlyDictionary<string, string?> row, string field) =>
        row.TryGetValue(field, out var value) ? value : null;

    private static List<string> ParseAssociatedCsvIds(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : Regex.Split(value, @"[;|]").Where(item => !string.IsNullOrWhiteSpace(item)).ToList();

    private static FiberEmailContactValue ToValue(FiberEmailContactEntry row) =>
        new(row.Name, row.Company, row.Email, row.Phone);

    private static OnpageEmailContactValue ToValue(OnpageEmailContactEntry row) =>
        new(row.Department, row.Email);

    private static NetworkOrderCircuitValue ToValue(NetworkOrderCircuitEntry row) =>
        new(row.ALocation, row.ZLocation, row.CircuitNetworkOrderId, row.Company, row.AssociatedCircuitNetworkOrderIds);

    private static NetworkOrderCircuitInput ToInput(NetworkOrderCircuitValue row) =>
        new(row.ALocation, row.ZLocation, row.CircuitNetworkOrderId, row.Company, row.AssociatedCircuitNetworkOrderIds);
}
