namespace NocIfc.Domain.Threat;

public sealed record CisaKevEntry(
    int Id,
    string? CveId,
    string? Vendor,
    string? Product,
    string? VulnerabilityName,
    DateTime? DateAdded,
    string? Description,
    string? RequiredAction,
    string? DueDate);
