using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class CloudStatusSyncCommands(ICloudStatusSyncProvider provider)
{
    public Task<CloudStatusSyncOutcome> ExecuteAsync(CancellationToken cancellationToken) =>
        provider.SyncAsync(cancellationToken);
}
