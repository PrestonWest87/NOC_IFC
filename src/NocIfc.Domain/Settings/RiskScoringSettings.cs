namespace NocIfc.Domain.Settings;

public sealed record RiskScoringSettings(
    string? ScoringMode,
    double? BaselineOverrideCyber,
    double? BaselineOverridePhys,
    int? CyberCriticalityOverride,
    int? CyberLethalityOverride,
    int? PhysicalCriticalityOverride,
    int? PhysicalLethalityOverride,
    int? InternalCriticalityOverride,
    int? InternalLethalityOverride,
    int? GlobalRiskOffset,
    int? InternalRiskOffset,
    int? SysCountermeasures,
    int? NetCountermeasures);
