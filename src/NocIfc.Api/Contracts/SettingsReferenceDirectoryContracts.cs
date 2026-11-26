using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class FiberEmailContactsUpdateRequest
{
    [JsonPropertyName("contacts")]
    public List<FiberEmailContactRequest>? Contacts { get; init; }

    public IReadOnlyList<FiberEmailContactInput> ToInputs() =>
        Contacts?.Select(contact => contact?.ToInput() ?? throw new ArgumentException("Each contact must be an object.")).ToArray()
        ?? throw new ArgumentException("contacts must be a list.");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class FiberEmailContactRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("company")]
    public string? Company { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("phone")]
    public string? Phone { get; init; }

    public FiberEmailContactInput ToInput() => new(Name, Company, Email, Phone);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class OnpageEmailContactsUpdateRequest
{
    [JsonPropertyName("contacts")]
    public List<OnpageEmailContactRequest>? Contacts { get; init; }

    public IReadOnlyList<OnpageEmailContactInput> ToInputs() =>
        Contacts?.Select(contact => contact?.ToInput() ?? throw new ArgumentException("Each contact must be an object.")).ToArray()
        ?? throw new ArgumentException("contacts must be a list.");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class OnpageEmailContactRequest
{
    [JsonPropertyName("department")]
    public string? Department { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    public OnpageEmailContactInput ToInput() => new(Department, Email);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NetworkOrderCircuitsUpdateRequest
{
    [JsonPropertyName("records")]
    public List<NetworkOrderCircuitRequest>? Records { get; init; }

    public IReadOnlyList<NetworkOrderCircuitInput> ToInputs() =>
        Records?.Select(record => record?.ToInput() ?? throw new ArgumentException("Each record must be an object.")).ToArray()
        ?? throw new ArgumentException("records must be a list.");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class NetworkOrderCircuitRequest
{
    [JsonPropertyName("a_location")]
    public string? ALocation { get; init; }

    [JsonPropertyName("z_location")]
    public string? ZLocation { get; init; }

    [JsonPropertyName("circuit_network_order_id")]
    public string? CircuitNetworkOrderId { get; init; }

    [JsonPropertyName("company")]
    public string? Company { get; init; }

    [JsonPropertyName("associated_circuit_network_order_ids")]
    public List<string>? AssociatedCircuitNetworkOrderIds { get; init; }

    public NetworkOrderCircuitInput ToInput() => new(
        ALocation,
        ZLocation,
        CircuitNetworkOrderId,
        Company,
        AssociatedCircuitNetworkOrderIds);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class SettingsDirectoryCsvImportRequest
{
    [JsonPropertyName("csv_text")]
    public string? CsvText { get; init; }

    [JsonPropertyName("mode")]
    public string? Mode { get; init; } = "merge";

    public (string CsvText, string Mode) ToImport() =>
        (CsvText ?? throw new ArgumentException("CSV content is required."), Mode ?? "");
}

public sealed record FiberEmailContactResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("company")] string Company,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("phone")] string? Phone,
    [property: JsonPropertyName("sort_order")] int SortOrder)
{
    public static FiberEmailContactResponse From(FiberEmailContactEntry contact) => new(
        contact.Id, contact.Name, contact.Company, contact.Email, contact.Phone, contact.SortOrder);
}

public sealed record OnpageEmailContactResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("department")] string Department,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("sort_order")] int SortOrder)
{
    public static OnpageEmailContactResponse From(OnpageEmailContactEntry contact) => new(
        contact.Id, contact.Department, contact.Email, contact.SortOrder);
}

public sealed record NetworkOrderCircuitResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("a_location")] string ALocation,
    [property: JsonPropertyName("z_location")] string ZLocation,
    [property: JsonPropertyName("circuit_network_order_id")] string CircuitNetworkOrderId,
    [property: JsonPropertyName("company")] string Company,
    [property: JsonPropertyName("associated_circuit_network_order_ids")] IReadOnlyList<string> AssociatedCircuitNetworkOrderIds,
    [property: JsonPropertyName("sort_order")] int SortOrder)
{
    public static NetworkOrderCircuitResponse From(NetworkOrderCircuitEntry record) => new(
        record.Id,
        record.ALocation,
        record.ZLocation,
        record.CircuitNetworkOrderId,
        record.Company,
        record.AssociatedCircuitNetworkOrderIds,
        record.SortOrder);
}

public sealed record EmailContactsDirectoryResponse(
    [property: JsonPropertyName("fiber")] IReadOnlyList<FiberEmailContactResponse> Fiber,
    [property: JsonPropertyName("onpage")] IReadOnlyList<OnpageEmailContactResponse> Onpage)
{
    public static EmailContactsDirectoryResponse From(
        IReadOnlyList<FiberEmailContactEntry> fiber,
        IReadOnlyList<OnpageEmailContactEntry> onpage) => new(
        fiber.Select(FiberEmailContactResponse.From).ToArray(),
        onpage.Select(OnpageEmailContactResponse.From).ToArray());
}

public sealed record NetworkOrdersDirectoryResponse(
    [property: JsonPropertyName("records")] IReadOnlyList<NetworkOrderCircuitResponse> Records)
{
    public static NetworkOrdersDirectoryResponse From(IReadOnlyList<NetworkOrderCircuitEntry> records) => new(
        records.Select(NetworkOrderCircuitResponse.From).ToArray());
}

public sealed record FiberEmailContactsUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("contacts")] IReadOnlyList<FiberEmailContactResponse> Contacts);

public sealed record OnpageEmailContactsUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("contacts")] IReadOnlyList<OnpageEmailContactResponse> Contacts);

public sealed record NetworkOrderCircuitsUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("records")] IReadOnlyList<NetworkOrderCircuitResponse> Records);

public sealed record SettingsDirectoryImportResponse<T>(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("imported_rows")] int ImportedRows,
    [property: JsonPropertyName("added")] int Added,
    [property: JsonPropertyName("updated")] int Updated,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("rows")] IReadOnlyList<T> Rows)
{
    public static SettingsDirectoryImportResponse<T> From<TEntry>(
        SettingsDirectoryImportResult<TEntry> result,
        Func<TEntry, T> map) => new(
        "imported",
        result.Mode,
        result.ImportedRows,
        result.Added,
        result.Updated,
        result.Rows.Count,
        result.Rows.Select(map).ToArray());
}
