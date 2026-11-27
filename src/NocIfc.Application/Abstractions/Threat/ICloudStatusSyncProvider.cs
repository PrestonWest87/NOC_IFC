using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface ICloudStatusSyncProvider
{
    Task<CloudStatusSyncOutcome> SyncAsync(CancellationToken cancellationToken);
}
