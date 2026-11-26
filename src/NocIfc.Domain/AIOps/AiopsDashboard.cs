using NocIfc.Domain.Settings;

namespace NocIfc.Domain.AIOps;

public sealed record AiopsAlertEntry(
    int Id,
    string? EventType,
    string? Severity,
    string? NodeName,
    string? IpAddress,
    string? Status,
    string? SwTimestamp,
    string? Details,
    string? NodeLink,
    string? RawPayloadJson,
    string? MappedLocation,
    DateTime? ReceivedAt,
    DateTime? ResolvedAt,
    bool IsDispatched,
    bool IsTicketed,
    bool IsCorrelated,
    bool NeedsDispatch,
    string? AiRootCause,
    string? DeviceType,
    string? EventCategory,
    string? AcknowledgedBy,
    DateTime? AcknowledgedAt,
    string? DispatchedBy,
    DateTime? DispatchedAt,
    DateTime? OnpageSentAt);

public sealed record AiopsTimelineEventEntry(
    int Id,
    DateTime? Timestamp,
    string? Source,
    string? EventType,
    string? Message,
    string? SiteName);

public sealed record AiopsRegionalOutageEntry(
    int Id,
    string? OutageType,
    string? Provider,
    string? Description,
    string? AffectedArea,
    double? Latitude,
    double? Longitude,
    double RadiusKilometers,
    DateTime? DetectedAt,
    bool IsResolved);

public sealed record AiopsBoardSnapshot(
    IReadOnlyList<AiopsAlertEntry> Alerts,
    IReadOnlyList<AiopsTimelineEventEntry> Events,
    IReadOnlyList<AiopsRegionalOutageEntry> Grid,
    IReadOnlyDictionary<string, int> ActiveIssueCounts,
    IReadOnlyList<MonitoredLocationEntry> Locations,
    IReadOnlyList<string> InvestigatingSites,
    bool IsAdministrator);

public enum AiopsNeedsDispatchOutcome
{
    Updated,
    SiteScopeDenied,
    SiteNotFound,
    ActiveAlertRequired,
}

public sealed record AiopsNeedsDispatchUpdate(AiopsNeedsDispatchOutcome Outcome, int UpdatedAlerts);
