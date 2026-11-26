using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Abstractions.Settings;

public interface IOperationalIntegrationSettingsStore
{
    Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken);
    Task<ElasticClientSettings> GetElasticClientSettingsAsync(CancellationToken cancellationToken);
    Task SaveAsync(OperationalIntegrationSettingsUpdate update, int actorUserId, CancellationToken cancellationToken);
}
