using NocIfc.Application.Abstractions.Settings;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.Settings;

public sealed class RiskScoringCommands(IRiskScoringSettingsStore settings)
{
    public Task<RiskScoringSettings?> GetAsync(CancellationToken cancellationToken) =>
        settings.GetAsync(cancellationToken);

    public async Task UpdateAsync(RiskScoringSettings update, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (update.ScoringMode is not null && update.ScoringMode is not ("auto" or "manual" or "hybrid"))
        {
            throw new ArgumentException("scoring_mode must be one of: auto, manual, hybrid.");
        }
        ValidateRange(update.BaselineOverrideCyber, 0, 5, "baseline_override_cyber");
        ValidateRange(update.BaselineOverridePhys, 0, 5, "baseline_override_phys");
        ValidateRange(update.CyberCriticalityOverride, 0, 5, "cyber_criticality_override");
        ValidateRange(update.CyberLethalityOverride, 0, 5, "cyber_lethality_override");
        ValidateRange(update.PhysicalCriticalityOverride, 0, 5, "physical_criticality_override");
        ValidateRange(update.PhysicalLethalityOverride, 0, 5, "physical_lethality_override");
        ValidateRange(update.InternalCriticalityOverride, 0, 5, "internal_criticality_override");
        ValidateRange(update.InternalLethalityOverride, 0, 5, "internal_lethality_override");
        ValidateRange(update.GlobalRiskOffset, -3, 3, "global_risk_offset");
        ValidateRange(update.InternalRiskOffset, -3, 3, "internal_risk_offset");
        ValidateRange(update.SysCountermeasures, 1, 5, "sys_countermeasures");
        ValidateRange(update.NetCountermeasures, 1, 5, "net_countermeasures");

        if (update == new RiskScoringSettings(null, null, null, null, null, null, null, null, null, null, null, null, null))
        {
            throw new ArgumentException("Provide at least one risk-scoring setting.");
        }
        await settings.UpdateAsync(update, cancellationToken);
    }

    private static void ValidateRange(double? value, double minimum, double maximum, string name)
    {
        if (value is not null && (double.IsNaN(value.Value) || value < minimum || value > maximum))
        {
            throw new ArgumentException($"{name} must be between {minimum} and {maximum}.");
        }
    }

    private static void ValidateRange(int? value, int minimum, int maximum, string name)
    {
        if (value is not null && (value < minimum || value > maximum))
        {
            throw new ArgumentException($"{name} must be between {minimum} and {maximum}.");
        }
    }
}
