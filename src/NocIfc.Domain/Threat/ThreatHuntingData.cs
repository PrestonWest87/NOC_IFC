namespace NocIfc.Domain.Threat;

public sealed record ExtractedIocEntry(
    int Id,
    string? IndicatorType,
    string? IndicatorValue,
    string? Context,
    DateTime? DetectedAt,
    string? SourceLink,
    string? SourceTitle);

public sealed record ElasticEventEntry(
    string Id,
    DateTime? Timestamp,
    string? IndexName,
    string? Severity,
    string? Message,
    string? SourceIp,
    string? EventCategory,
    string? LegacyId = null);

public sealed record PagedElasticEvents(
    IReadOnlyList<ElasticEventEntry> Items,
    int Total,
    int Page,
    int PageSize,
    int HoursBack);
