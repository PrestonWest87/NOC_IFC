using NocIfc.Domain.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IRiskScoringSettingsStore
{
    Task<RiskScoringSettings?> GetAsync(CancellationToken cancellationToken);
    Task UpdateAsync(RiskScoringSettings settings, CancellationToken cancellationToken);
}
