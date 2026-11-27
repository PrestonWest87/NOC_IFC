using NocIfc.Domain.Threat;

namespace NocIfc.Domain.Reporting;

public sealed record DailyBriefingEntry(
    int Id,
    DateTime? ReportDate,
    string? Content,
    DateTime? CreatedAt);

public sealed record DailyFusionHazard(string? Severity, string? Title, string? Location);
public sealed record DailyFusionCloudOutage(string? Provider, string? Service, string? Title);

public sealed record DailyFusionInputs(
    IReadOnlyList<ThreatArticle> Articles,
    IReadOnlyList<CisaKevEntry> Cves,
    IReadOnlyList<DailyFusionHazard> Hazards,
    IReadOnlyList<DailyFusionCloudOutage> CloudOutages);
