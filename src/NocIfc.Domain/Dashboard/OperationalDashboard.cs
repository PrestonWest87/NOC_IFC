using System.Text.Json;

namespace NocIfc.Domain.Dashboard;

public sealed record DashboardMetrics(int RssCount, int CveCount, int HazardCount, int CloudCount);

public sealed record DashboardRegionalHazard(
    int Id,
    string? HazardId,
    string? HazardType,
    string? Severity,
    string? Title,
    string? Description,
    string? Location,
    DateTime? UpdatedAt,
    DateTime? LastSeenAt,
    string Status,
    DateTime? SentAt,
    DateTime? EffectiveAt,
    DateTime? OnsetAt,
    DateTime? ExpiresAt,
    DateTime? EventEndingAt,
    string? MessageType,
    JsonElement? ReferencesJson,
    string? CoverageScope,
    string? CoveragePrecision);

public sealed record DailyThreatScoreEntry(
    int Id,
    DateTime? RecordDate,
    double? CyberPoints,
    double? PhysicalPoints,
    double? CyberBaseline,
    double? PhysicalBaseline);

public sealed record DashboardBriefSnapshot(
    string? RollingSummary,
    DateTime? RollingSummaryTime,
    string? GlobalBrief,
    DateTime? GlobalBriefTime,
    string? InternalBrief,
    DateTime? InternalBriefTime,
    string? UnifiedBrief,
    DateTime? UnifiedBriefTime,
    string? LastGlobalRisk = null,
    string? LastInternalRisk = null);
