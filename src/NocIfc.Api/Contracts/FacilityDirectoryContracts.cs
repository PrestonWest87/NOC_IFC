using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

public sealed record MonitoredLocationResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("lat")] double? Latitude,
    [property: JsonPropertyName("lon")] double? Longitude,
    [property: JsonPropertyName("loc_type")] string? LocationType,
    [property: JsonPropertyName("district")] string? District,
    [property: JsonPropertyName("priority")] string? Priority,
    [property: JsonPropertyName("current_spc_risk")] string? CurrentSpcRisk,
    [property: JsonPropertyName("last_updated")] DateTime? LastUpdated,
    [property: JsonPropertyName("under_maintenance")] bool? UnderMaintenance,
    [property: JsonPropertyName("maintenance_etr")] DateTime? MaintenanceEtr,
    [property: JsonPropertyName("maintenance_reason")] string? MaintenanceReason,
    [property: JsonPropertyName("last_auto_ticket")] DateTime? LastAutoTicket,
    [property: JsonPropertyName("last_escalation_ticket")] DateTime? LastEscalationTicket,
    [property: JsonPropertyName("last_auto_dispatch")] DateTime? LastAutoDispatch,
    [property: JsonPropertyName("last_escalation_dispatch")] DateTime? LastEscalationDispatch,
    [property: JsonPropertyName("status_modified_by")] string? StatusModifiedBy,
    [property: JsonPropertyName("status_modified_at")] DateTime? StatusModifiedAt)
{
    public static MonitoredLocationResponse From(MonitoredLocationEntry location) => new(
        location.Id,
        location.Name,
        location.Latitude,
        location.Longitude,
        location.LocationType,
        location.District,
        location.Priority,
        location.CurrentSpcRisk,
        location.LastUpdated,
        location.UnderMaintenance,
        location.MaintenanceEtr,
        location.MaintenanceReason,
        location.LastAutoTicket,
        location.LastEscalationTicket,
        location.LastAutoDispatch,
        location.LastEscalationDispatch,
        location.StatusModifiedBy,
        location.StatusModifiedAt);
}

public sealed class LocationImportRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("lat")]
    public JsonElement? Latitude { get; init; }

    [JsonPropertyName("lon")]
    public JsonElement? Longitude { get; init; }

    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("loc_type")]
    public string? LocationType { get; init; }

    [JsonPropertyName("district")]
    public string? District { get; init; } = "Central";

    [JsonPropertyName("priority")]
    public string? Priority { get; init; } = "P3-Moderate";

    public MonitoredLocationImportRow ToRow() => new(
        Name,
        Number(Latitude, "lat"),
        Number(Longitude, "lon"),
        Type,
        LocationType,
        District,
        Priority);

    private static double? Number(JsonElement? raw, string field)
    {
        if (raw is null || raw.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (raw.Value.ValueKind == JsonValueKind.Number && raw.Value.TryGetDouble(out var number))
        {
            return number;
        }
        if (raw.Value.ValueKind == JsonValueKind.String
            && double.TryParse(raw.Value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
        {
            return number;
        }
        throw new ArgumentException($"{field} must be a number.");
    }
}

public sealed class LocationEditRequest
{
    [JsonPropertyName("id")]
    public JsonElement? Id { get; init; }

    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("loc_type")]
    public string? LocationType { get; init; }

    [JsonPropertyName("type")]
    public string? Type { get; init; }

    [JsonPropertyName("district")]
    public string? District { get; init; }

    [JsonPropertyName("priority")]
    public string? Priority { get; init; }

    [JsonPropertyName("lat")]
    public JsonElement? Latitude { get; init; }

    [JsonPropertyName("lon")]
    public JsonElement? Longitude { get; init; }

    public MonitoredLocationEditRow ToRow() => new(
        Integer(Id, "id"), Name, LocationType, Type, District, Priority,
        Number(Latitude, "lat"), Number(Longitude, "lon"));

    private static int? Integer(JsonElement? raw, string field)
    {
        if (raw is null || raw.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (raw.Value.ValueKind == JsonValueKind.Number && raw.Value.TryGetInt32(out var number))
        {
            return number;
        }
        throw new ArgumentException($"{field} must be an integer.");
    }

    private static double? Number(JsonElement? raw, string field)
    {
        if (raw is null || raw.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        if (raw.Value.ValueKind == JsonValueKind.Number && raw.Value.TryGetDouble(out var number))
        {
            return number;
        }
        if (raw.Value.ValueKind == JsonValueKind.String
            && double.TryParse(raw.Value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number))
        {
            return number;
        }
        throw new ArgumentException($"{field} must be a number.");
    }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class SiteContactsUpdateRequest
{
    [JsonPropertyName("contacts")]
    public List<SiteContactRequest>? Contacts { get; init; }

    public IReadOnlyList<SiteContactInput> ToInputs() =>
        Contacts?.Select(contact => contact?.ToInput()
            ?? throw new ArgumentException("Each site contact must be an object.")).ToArray()
        ?? throw new ArgumentException("contacts must be a list.");
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class SiteContactRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("phone")]
    public string? Phone { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    public SiteContactInput ToInput() => new(Name, Phone, Email);
}

public sealed record SiteContactResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("phone")] string? Phone,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("sort_order")] int SortOrder)
{
    public static SiteContactResponse From(MonitoredLocationContactEntry contact) => new(
        contact.Id, contact.Name, contact.Phone, contact.Email, contact.SortOrder);
}

public sealed record SiteContactsUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("contacts")] IReadOnlyList<SiteContactResponse> Contacts);

public sealed record SiteContactsResponse(
    [property: JsonPropertyName("contacts")] IReadOnlyList<SiteContactResponse> Contacts)
{
    public static SiteContactsResponse From(IReadOnlyList<MonitoredLocationContactEntry> contacts) => new(
        contacts.Select(SiteContactResponse.From).ToArray());
}
