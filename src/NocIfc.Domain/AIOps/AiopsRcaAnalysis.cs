namespace NocIfc.Domain.AIOps;

public sealed record AiopsRcaAnalysisContext(
    IReadOnlyList<AiopsCloudOutageEntry> CloudOutages,
    IReadOnlyList<AiopsWeatherHazardEntry> ActiveWeather,
    IReadOnlyList<AiopsBgpAnomalyEntry> ActiveBgp,
    IReadOnlyList<AiopsHistoricalAlertEntry> RecentAlerts);

public sealed record AiopsCloudOutageEntry(string? Provider);
public sealed record AiopsWeatherHazardEntry(string? HazardType, string? Location);
public sealed record AiopsBgpAnomalyEntry(string? Asn);

public sealed record AiopsHistoricalAlertEntry(
    string? NodeName,
    string? DeviceType,
    string? MappedLocation,
    string? RawPayloadJson,
    string? Status);

public sealed record AiopsRcaDependencyEntry(
    AiopsAlertEntry Alert,
    double Score,
    string Domain,
    string NodeType,
    int Severity);

public sealed record AiopsRcaSiteMetadata(
    string PrimaryComms,
    string SecondaryComms,
    string District);

public sealed record AiopsRcaCluster(
    IReadOnlyList<AiopsAlertEntry> Alerts,
    AiopsRcaSiteMetadata SiteMetadata,
    IReadOnlyList<string> DomainsAffected,
    IReadOnlyList<AiopsRcaDependencyEntry> DependencyChain,
    IReadOnlyList<double> AverageLoss,
    IReadOnlyList<double> AverageCpu,
    IReadOnlyList<string> Ips,
    int MaximumAlertLevel,
    AiopsAlertEntry? LatestAlert,
    AiopsAlertEntry? PatientZero);

public sealed record AiopsFleetEvent(
    string Provider,
    IReadOnlyList<string> AffectedSites,
    string EventType,
    string Severity);

public sealed record AiopsRootCause(
    string Cause,
    int Score,
    string Priority,
    IReadOnlyList<string> Evidence,
    string BlastRadius,
    string PatientZero,
    string CascadeDelay);

public sealed record AiopsChronicNodeSummary(
    string NodeName,
    int IncidentCount,
    string? DeviceType,
    string Site);

public sealed record AiopsChronicSiteSummary(string Site, int IncidentCount);

public sealed record AiopsChronicInsights(
    IReadOnlyList<AiopsChronicNodeSummary> OffendingNodes,
    IReadOnlyList<AiopsChronicSiteSummary> Hotspots,
    IReadOnlyList<string> Forecast);

public sealed record AiopsRcaAnalysisResult(
    IReadOnlyDictionary<string, AiopsRcaCluster> Clustered,
    IReadOnlyList<AiopsFleetEvent> FleetOutages,
    IReadOnlyDictionary<string, AiopsRootCause> RootCause,
    IReadOnlyList<AiopsTimelineEventEntry> Events,
    bool CanViewChronicInsights,
    AiopsChronicInsights? ChronicInsights,
    int ActiveCloudOutageCount,
    int ActiveWeatherHazardCount);
