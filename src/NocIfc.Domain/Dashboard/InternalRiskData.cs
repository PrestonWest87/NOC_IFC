using System.Text.Json;

namespace NocIfc.Domain.Dashboard;

public sealed record InternalRiskSnapshotEntry(
    int Id,
    DateTime? Timestamp,
    double? Score,
    string? RiskLevel,
    int? TotalAssets,
    int? TotalOsintHits,
    int? CriticalOsintHits,
    JsonElement HardwareData,
    JsonElement SoftwareData,
    string ScoringMode);

public sealed record InternalRiskHistoryPoint(DateTime? Timestamp, double? Score, string? RiskLevel);
