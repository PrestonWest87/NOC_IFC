using System.Text.Json.Serialization;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed record CisaKevResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("cve_id")] string? CveId,
    [property: JsonPropertyName("vendor")] string? Vendor,
    [property: JsonPropertyName("product")] string? Product,
    [property: JsonPropertyName("vulnerability_name")] string? VulnerabilityName,
    [property: JsonPropertyName("date_added")] DateTime? DateAdded,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("required_action")] string? RequiredAction,
    [property: JsonPropertyName("due_date")] string? DueDate)
{
    public static CisaKevResponse From(CisaKevEntry entry) => new(
        entry.Id,
        entry.CveId,
        entry.Vendor,
        entry.Product,
        entry.VulnerabilityName,
        entry.DateAdded,
        entry.Description,
        entry.RequiredAction,
        entry.DueDate);
}
