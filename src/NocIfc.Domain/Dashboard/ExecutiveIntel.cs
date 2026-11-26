using NocIfc.Domain.Settings;
using NocIfc.Domain.Threat;

namespace NocIfc.Domain.Dashboard;

public sealed record ExecutiveIntelInputs(
    RiskScoringSettings? RiskSettings,
    IReadOnlyList<DailyThreatScoreEntry> ScoreHistory,
    IReadOnlyList<ThreatArticle> CyberCandidates,
    IReadOnlyList<ThreatArticle> RecentArticles,
    IReadOnlyList<ThreatArticle> PhysicalCandidates,
    IReadOnlyList<CisaKevEntry> RecentCves,
    IReadOnlyList<CrimeIncidentEntry> RecentCrimes,
    int ActiveWarningCount);

public sealed record ExecutiveIntelArticle(
    ThreatArticle Article,
    bool IsUtilityRelated,
    bool IsAptRelated,
    bool IsRansomware);

public sealed record ExecutiveIntelCrime(CrimeIncidentEntry Incident, string FbiCategory);

public sealed record ExecutiveRiskOverride(int Auto, int Used);

public sealed record ExecutiveRiskOverrides(
    ExecutiveRiskOverride CyberCriticality,
    ExecutiveRiskOverride CyberLethality,
    ExecutiveRiskOverride PhysicalCriticality,
    ExecutiveRiskOverride PhysicalLethality);

public sealed record ExecutiveIntelReport(
    string Timestamp,
    string UnifiedRisk,
    string PhysicalScore,
    string PhysicalBrief,
    string CyberScore,
    string CyberBrief,
    int CisCyberScore,
    IReadOnlyList<ExecutiveIntelCrime> RecentCrimes,
    IReadOnlyList<ExecutiveIntelArticle> RawCyberArticles,
    IReadOnlyList<ThreatArticle> RawPhysicalArticles,
    IReadOnlyList<string> EvidenceLog,
    int CurrentCyberPoints,
    int CurrentPhysicalPoints,
    double BaselineCyber,
    double BaselinePhysical,
    string ScoringMode,
    ExecutiveRiskOverrides AppliedOverrides);
