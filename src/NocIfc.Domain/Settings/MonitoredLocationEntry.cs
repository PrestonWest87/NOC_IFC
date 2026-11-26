namespace NocIfc.Domain.Settings;

public sealed record MonitoredLocationEntry(
    int Id,
    string? Name,
    double? Latitude,
    double? Longitude,
    string? LocationType,
    string? District,
    string? Priority,
    string? CurrentSpcRisk,
    DateTime? LastUpdated,
    bool? UnderMaintenance,
    DateTime? MaintenanceEtr,
    string? MaintenanceReason,
    DateTime? LastAutoTicket,
    DateTime? LastEscalationTicket,
    DateTime? LastAutoDispatch,
    DateTime? LastEscalationDispatch,
    string? StatusModifiedBy,
    DateTime? StatusModifiedAt);

public sealed record MonitoredLocationContactEntry(
    int Id,
    string? Name,
    string? Phone,
    string? Email,
    int SortOrder);

public sealed record MonitoredLocationContactValue(string? Name, string? Phone, string? Email);
