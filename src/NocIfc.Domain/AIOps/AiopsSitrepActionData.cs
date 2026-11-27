namespace NocIfc.Domain.AIOps;

public sealed record AiopsRollingBriefHazard(
    string? Severity,
    string? Title,
    string? Location,
    string? Description);

public sealed record AiopsRollingBriefCloudOutage(
    string? Provider,
    string? Service,
    string? Title);

public sealed record AiopsRollingBriefInputs(
    IReadOnlyList<string?> ArticleTitles,
    IReadOnlyList<AiopsRollingBriefHazard> Hazards,
    IReadOnlyList<AiopsRollingBriefCloudOutage> CloudOutages);
