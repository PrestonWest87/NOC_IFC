using System.Text.Json;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Domain.Dashboard;

namespace NocIfc.Api.Contracts;

public sealed record DashboardMetricsResponse(
    [property: JsonPropertyName("rss_count")] int RssCount,
    [property: JsonPropertyName("cve_count")] int CveCount,
    [property: JsonPropertyName("hazard_count")] int HazardCount,
    [property: JsonPropertyName("cloud_count")] int CloudCount)
{
    public static DashboardMetricsResponse From(DashboardMetrics metrics) => new(
        metrics.RssCount, metrics.CveCount, metrics.HazardCount, metrics.CloudCount);
}

public sealed record DashboardRegionalHazardResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("hazard_id")] string? HazardId,
    [property: JsonPropertyName("hazard_type")] string? HazardType,
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("location")] string? Location,
    [property: JsonPropertyName("updated_at")] DateTime? UpdatedAt,
    [property: JsonPropertyName("last_seen_at")] DateTime? LastSeenAt,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("sent_at")] DateTime? SentAt,
    [property: JsonPropertyName("effective_at")] DateTime? EffectiveAt,
    [property: JsonPropertyName("onset_at")] DateTime? OnsetAt,
    [property: JsonPropertyName("expires_at")] DateTime? ExpiresAt,
    [property: JsonPropertyName("event_ending_at")] DateTime? EventEndingAt,
    [property: JsonPropertyName("message_type")] string? MessageType,
    [property: JsonPropertyName("references_json")] JsonElement? ReferencesJson,
    [property: JsonPropertyName("coverage_scope")] string? CoverageScope,
    [property: JsonPropertyName("coverage_precision")] string? CoveragePrecision)
{
    public static DashboardRegionalHazardResponse From(DashboardRegionalHazard hazard) => new(
        hazard.Id,
        hazard.HazardId,
        hazard.HazardType,
        hazard.Severity,
        hazard.Title,
        hazard.Description,
        hazard.Location,
        hazard.UpdatedAt,
        hazard.LastSeenAt,
        hazard.Status,
        hazard.SentAt,
        hazard.EffectiveAt,
        hazard.OnsetAt,
        hazard.ExpiresAt,
        hazard.EventEndingAt,
        hazard.MessageType,
        hazard.ReferencesJson,
        hazard.CoverageScope,
        hazard.CoveragePrecision);
}

public sealed record DailyThreatScoreResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("record_date")] DateTime? RecordDate,
    [property: JsonPropertyName("cyber_points")] double? CyberPoints,
    [property: JsonPropertyName("physical_points")] double? PhysicalPoints,
    [property: JsonPropertyName("cyber_baseline")] double? CyberBaseline,
    [property: JsonPropertyName("physical_baseline")] double? PhysicalBaseline)
{
    public static DailyThreatScoreResponse From(DailyThreatScoreEntry score) => new(
        score.Id,
        score.RecordDate,
        score.CyberPoints,
        score.PhysicalPoints,
        score.CyberBaseline,
        score.PhysicalBaseline);
}

public sealed record InternalRiskHistoryResponse(
    [property: JsonPropertyName("timestamp")] DateTime? Timestamp,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("risk_level")] string? RiskLevel)
{
    public static InternalRiskHistoryResponse From(InternalRiskHistoryPoint point) => new(
        point.Timestamp, point.Score, point.RiskLevel);
}

public sealed record InternalRiskResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("timestamp")] DateTime? Timestamp,
    [property: JsonPropertyName("score")] double? Score,
    [property: JsonPropertyName("risk_level")] string? RiskLevel,
    [property: JsonPropertyName("total_assets")] int? TotalAssets,
    [property: JsonPropertyName("total_osint_hits")] int? TotalOsintHits,
    [property: JsonPropertyName("critical_osint_hits")] int? CriticalOsintHits,
    [property: JsonPropertyName("hw_data")] JsonElement HardwareData,
    [property: JsonPropertyName("sw_data")] JsonElement SoftwareData,
    [property: JsonPropertyName("scoring_mode")] string ScoringMode,
    [property: JsonPropertyName("applied_overrides")] object AppliedOverrides)
{
    public static InternalRiskResponse From(InternalRiskSnapshotEntry snapshot) => new(
        snapshot.Id,
        snapshot.Timestamp,
        snapshot.Score,
        snapshot.RiskLevel,
        snapshot.TotalAssets,
        snapshot.TotalOsintHits,
        snapshot.CriticalOsintHits,
        snapshot.HardwareData,
        snapshot.SoftwareData,
        snapshot.ScoringMode,
        new
        {
            criticality = new { auto = "stored", used = "stored" },
            lethality = new { auto = "stored", used = "stored" },
        });
}

public sealed record InternalRiskAppliedOverrideResponse(
    [property: JsonPropertyName("auto")] int Auto,
    [property: JsonPropertyName("used")] int Used);

public sealed record InternalRiskAppliedOverridesResponse(
    [property: JsonPropertyName("criticality")] InternalRiskAppliedOverrideResponse Criticality,
    [property: JsonPropertyName("lethality")] InternalRiskAppliedOverrideResponse Lethality);

public sealed record InternalRiskGenerationResponse(
    [property: JsonPropertyName("score")] int Score,
    [property: JsonPropertyName("risk_level")] string RiskLevel,
    [property: JsonPropertyName("total_assets")] int TotalAssets,
    [property: JsonPropertyName("total_hw_loaded")] int TotalHardwareLoaded,
    [property: JsonPropertyName("total_sw_loaded")] int TotalSoftwareLoaded,
    [property: JsonPropertyName("total_osint_hits")] int TotalOsintHits,
    [property: JsonPropertyName("critical_osint_hits")] int CriticalOsintHits,
    [property: JsonPropertyName("hw_data")] JsonElement HardwareData,
    [property: JsonPropertyName("sw_data")] JsonElement SoftwareData,
    [property: JsonPropertyName("scoring_mode")] string ScoringMode,
    [property: JsonPropertyName("applied_overrides")] InternalRiskAppliedOverridesResponse AppliedOverrides)
{
    public static InternalRiskGenerationResponse From(InternalRiskScoringResult result) => new(
        result.Score,
        result.RiskLevel,
        result.TotalAssets,
        result.TotalHardwareLoaded,
        result.TotalSoftwareLoaded,
        result.TotalOsintHits,
        result.CriticalOsintHits,
        result.HardwareData,
        result.SoftwareData,
        result.ScoringMode,
        new InternalRiskAppliedOverridesResponse(
            new InternalRiskAppliedOverrideResponse(result.AutoCriticality, result.Criticality),
            new InternalRiskAppliedOverrideResponse(result.AutoLethality, result.Lethality)));
}
