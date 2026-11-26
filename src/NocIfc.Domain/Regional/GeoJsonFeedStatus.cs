namespace NocIfc.Domain.Regional;

public sealed record GeoJsonFeedStatus(
    string FeedName,
    DateTime? UpdatedAt,
    DateTime? LastAttemptAt,
    DateTime? LastSuccessAt,
    string? LastError,
    int? LastHttpStatus,
    int? LastDurationMs,
    DateTime? RetryAfterAt,
    int? FeatureCount,
    string? CoverageSummaryJson);
