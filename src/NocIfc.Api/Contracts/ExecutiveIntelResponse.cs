using System.Text.Json.Serialization;
using NocIfc.Domain.Dashboard;

namespace NocIfc.Api.Contracts;

public sealed record ExecutiveIntelCrimeResponse(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("category")] string? Category,
    [property: JsonPropertyName("raw_title")] string? RawTitle,
    [property: JsonPropertyName("timestamp")] string? Timestamp,
    [property: JsonPropertyName("distance_miles")] double? DistanceMiles,
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("lat")] double? Latitude,
    [property: JsonPropertyName("lon")] double? Longitude,
    [property: JsonPropertyName("fbi_category")] string FbiCategory)
{
    public static ExecutiveIntelCrimeResponse From(ExecutiveIntelCrime crime) => new(
        crime.Incident.Id,
        crime.Incident.Category,
        crime.Incident.RawTitle,
        CrimeIncidentResponse.From(crime.Incident).Timestamp,
        crime.Incident.DistanceMiles,
        crime.Incident.Severity,
        crime.Incident.Latitude,
        crime.Incident.Longitude,
        crime.FbiCategory);
}

public sealed record ExecutiveIntelResponse(
    [property: JsonPropertyName("timestamp")] string Timestamp,
    [property: JsonPropertyName("unified_risk")] string UnifiedRisk,
    [property: JsonPropertyName("physical_score")] string PhysicalScore,
    [property: JsonPropertyName("physical_brief")] string PhysicalBrief,
    [property: JsonPropertyName("cyber_score")] string CyberScore,
    [property: JsonPropertyName("cyber_brief")] string CyberBrief,
    [property: JsonPropertyName("cis_cyber_score")] int CisCyberScore,
    [property: JsonPropertyName("recent_crimes")] IReadOnlyList<ExecutiveIntelCrimeResponse> RecentCrimes,
    [property: JsonPropertyName("raw_cyber_articles")] IReadOnlyList<ThreatArticleResponse> RawCyberArticles,
    [property: JsonPropertyName("raw_phys_articles")] IReadOnlyList<ThreatArticleResponse> RawPhysicalArticles,
    [property: JsonPropertyName("evidence_log")] IReadOnlyList<string> EvidenceLog,
    [property: JsonPropertyName("current_cyber_pts")] int CurrentCyberPoints,
    [property: JsonPropertyName("current_phys_pts")] int CurrentPhysicalPoints,
    [property: JsonPropertyName("baseline_cyber")] double BaselineCyber,
    [property: JsonPropertyName("baseline_phys")] double BaselinePhysical,
    [property: JsonPropertyName("scoring_mode")] string ScoringMode,
    [property: JsonPropertyName("applied_overrides")] object AppliedOverrides)
{
    public static ExecutiveIntelResponse From(ExecutiveIntelReport report) => new(
        report.Timestamp,
        report.UnifiedRisk,
        report.PhysicalScore,
        report.PhysicalBrief,
        report.CyberScore,
        report.CyberBrief,
        report.CisCyberScore,
        report.RecentCrimes.Select(ExecutiveIntelCrimeResponse.From).ToArray(),
        report.RawCyberArticles.Select(ThreatArticleResponse.FromExecutive).ToArray(),
        report.RawPhysicalArticles.Select(ThreatArticleResponse.From).ToArray(),
        report.EvidenceLog,
        report.CurrentCyberPoints,
        report.CurrentPhysicalPoints,
        report.BaselineCyber,
        report.BaselinePhysical,
        report.ScoringMode,
        new
        {
            cyber_criticality = new
            {
                auto = report.AppliedOverrides.CyberCriticality.Auto,
                used = report.AppliedOverrides.CyberCriticality.Used,
            },
            cyber_lethality = new
            {
                auto = report.AppliedOverrides.CyberLethality.Auto,
                used = report.AppliedOverrides.CyberLethality.Used,
            },
            physical_criticality = new
            {
                auto = report.AppliedOverrides.PhysicalCriticality.Auto,
                used = report.AppliedOverrides.PhysicalCriticality.Used,
            },
            physical_lethality = new
            {
                auto = report.AppliedOverrides.PhysicalLethality.Auto,
                used = report.AppliedOverrides.PhysicalLethality.Used,
            },
        });
}
