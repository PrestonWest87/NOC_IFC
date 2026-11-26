using System.Text.Json.Serialization;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class ApplicationSettingsUpdateRequest
{
    [JsonPropertyName("public_app_url")]
    public string? PublicAppUrl { get; init; }

    [JsonPropertyName("tech_stack")]
    public string? TechStack { get; init; }

    [JsonPropertyName("monitored_asns")]
    public string? MonitoredAsns { get; init; }

    [JsonPropertyName("failed_login_alert_enabled")]
    public bool? FailedLoginAlertEnabled { get; init; }

    [JsonPropertyName("failed_login_alert_recipients")]
    public string? FailedLoginAlertRecipients { get; init; }

    [JsonPropertyName("failed_login_alert_threshold")]
    public int? FailedLoginAlertThreshold { get; init; }

    [JsonPropertyName("failed_login_alert_window_minutes")]
    public int? FailedLoginAlertWindowMinutes { get; init; }

    public GlobalApplicationSettingsUpdate ToUpdate() => new(
        PublicAppUrl,
        TechStack,
        MonitoredAsns,
        FailedLoginAlertEnabled,
        FailedLoginAlertRecipients,
        FailedLoginAlertThreshold,
        FailedLoginAlertWindowMinutes);
}

public sealed record ApplicationSettingsResponse(
    [property: JsonPropertyName("public_app_url")] string PublicAppUrl,
    [property: JsonPropertyName("tech_stack")] string TechStack,
    [property: JsonPropertyName("monitored_asns")] string MonitoredAsns,
    [property: JsonPropertyName("failed_login_alert_enabled")] bool FailedLoginAlertEnabled,
    [property: JsonPropertyName("failed_login_alert_recipients")] string FailedLoginAlertRecipients,
    [property: JsonPropertyName("failed_login_alert_threshold")] int FailedLoginAlertThreshold,
    [property: JsonPropertyName("failed_login_alert_window_minutes")] int FailedLoginAlertWindowMinutes)
{
    public static ApplicationSettingsResponse From(GlobalApplicationSettings settings) => new(
        settings.PublicAppUrl,
        settings.TechStack,
        settings.MonitoredAsns,
        settings.FailedLoginAlertEnabled,
        settings.FailedLoginAlertRecipients,
        settings.FailedLoginAlertThreshold,
        settings.FailedLoginAlertWindowMinutes);
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class RiskScoringSettingsRequest
{
    [JsonPropertyName("scoring_mode")]
    public string? ScoringMode { get; init; }

    [JsonPropertyName("baseline_override_cyber")]
    public double? BaselineOverrideCyber { get; init; }

    [JsonPropertyName("baseline_override_phys")]
    public double? BaselineOverridePhys { get; init; }

    [JsonPropertyName("cyber_criticality_override")]
    public int? CyberCriticalityOverride { get; init; }

    [JsonPropertyName("cyber_lethality_override")]
    public int? CyberLethalityOverride { get; init; }

    [JsonPropertyName("physical_criticality_override")]
    public int? PhysicalCriticalityOverride { get; init; }

    [JsonPropertyName("physical_lethality_override")]
    public int? PhysicalLethalityOverride { get; init; }

    [JsonPropertyName("internal_criticality_override")]
    public int? InternalCriticalityOverride { get; init; }

    [JsonPropertyName("internal_lethality_override")]
    public int? InternalLethalityOverride { get; init; }

    [JsonPropertyName("global_risk_offset")]
    public int? GlobalRiskOffset { get; init; }

    [JsonPropertyName("internal_risk_offset")]
    public int? InternalRiskOffset { get; init; }

    [JsonPropertyName("sys_countermeasures")]
    public int? SysCountermeasures { get; init; }

    [JsonPropertyName("net_countermeasures")]
    public int? NetCountermeasures { get; init; }

    public RiskScoringSettings ToSettings() => new(
        ScoringMode,
        BaselineOverrideCyber,
        BaselineOverridePhys,
        CyberCriticalityOverride,
        CyberLethalityOverride,
        PhysicalCriticalityOverride,
        PhysicalLethalityOverride,
        InternalCriticalityOverride,
        InternalLethalityOverride,
        GlobalRiskOffset,
        InternalRiskOffset,
        SysCountermeasures,
        NetCountermeasures);
}

public sealed record RiskScoringSettingsResponse(
    [property: JsonPropertyName("scoring_mode")] string? ScoringMode,
    [property: JsonPropertyName("baseline_override_cyber")] double? BaselineOverrideCyber,
    [property: JsonPropertyName("baseline_override_phys")] double? BaselineOverridePhys,
    [property: JsonPropertyName("cyber_criticality_override")] int? CyberCriticalityOverride,
    [property: JsonPropertyName("cyber_lethality_override")] int? CyberLethalityOverride,
    [property: JsonPropertyName("physical_criticality_override")] int? PhysicalCriticalityOverride,
    [property: JsonPropertyName("physical_lethality_override")] int? PhysicalLethalityOverride,
    [property: JsonPropertyName("internal_criticality_override")] int? InternalCriticalityOverride,
    [property: JsonPropertyName("internal_lethality_override")] int? InternalLethalityOverride,
    [property: JsonPropertyName("global_risk_offset")] int? GlobalRiskOffset,
    [property: JsonPropertyName("internal_risk_offset")] int? InternalRiskOffset,
    [property: JsonPropertyName("sys_countermeasures")] int? SysCountermeasures,
    [property: JsonPropertyName("net_countermeasures")] int? NetCountermeasures)
{
    public static RiskScoringSettingsResponse From(RiskScoringSettings settings) => new(
        settings.ScoringMode,
        settings.BaselineOverrideCyber,
        settings.BaselineOverridePhys,
        settings.CyberCriticalityOverride,
        settings.CyberLethalityOverride,
        settings.PhysicalCriticalityOverride,
        settings.PhysicalLethalityOverride,
        settings.InternalCriticalityOverride,
        settings.InternalLethalityOverride,
        settings.GlobalRiskOffset,
        settings.InternalRiskOffset,
        settings.SysCountermeasures,
        settings.NetCountermeasures);
}
