using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IOperationalIntegrationSettingsStore
{
    Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken);
    Task SaveAsync(OperationalIntegrationSettingsUpdate update, int actorUserId, CancellationToken cancellationToken);
}
