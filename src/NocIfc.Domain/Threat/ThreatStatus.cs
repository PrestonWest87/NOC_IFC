namespace NocIfc.Domain.Threat;

public sealed record CloudOutageEntry(
    int Id,
    string? Provider,
    string? Service,
    string? Title,
    string? Description,
    string? Link,
    bool? IsResolved,
    DateTime? UpdatedAt,
    string? ExternalId,
    string? StatusCode);

public sealed record CrimeIncidentEntry(
    string Id,
    string? Category,
    string? RawTitle,
    DateTime? Timestamp,
    double? DistanceMiles,
    string? Severity,
    double? Latitude,
    double? Longitude);

public sealed record Microsoft365FeedState(
    DateTime? LastAttemptAt,
    DateTime? LastSuccessAt,
    int? LastDurationMs,
    int? LastHttpStatus,
    string? LastError);

public sealed record Microsoft365StatusSnapshot(
    Microsoft365FeedState? FeedState,
    bool? CloudJobEnabled,
    int? CloudJobIntervalMinutes,
    IReadOnlyList<CloudOutageEntry> ActiveIncidents);

public sealed record Microsoft365ActiveIncident(
    int Id,
    string Title,
    string Service,
    string Description,
    string Link,
    string StatusCode,
    string StatusLabel,
    string? UpdatedAt);

public sealed record Microsoft365ServiceStatus(
    string Id,
    string Name,
    string Status,
    string StatusLabel,
    IReadOnlyList<Microsoft365ActiveIncident> ActiveIncidents);

public sealed record Microsoft365StatusReport(
    string Source,
    string SourceUrl,
    string FeedUrl,
    string FeedStatus,
    string? LastAttemptAt,
    string? LastSuccessAt,
    int? LastDurationMs,
    int? LastHttpStatus,
    string? LastError,
    int StaleAfterMinutes,
    IReadOnlyList<Microsoft365ServiceStatus> Services,
    IReadOnlyList<Microsoft365ActiveIncident> ActiveIncidents);

public sealed record CloudStatusSyncOutcome(
    int AddedCount,
    int ResolvedCount,
    int FilteredCount,
    IReadOnlyList<string> FailedProviders);

public sealed record CrimeDataSyncOutcome(int AddedCount, int AlertsDispatched);
