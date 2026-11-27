using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class CrimeDataSyncCommands(ICrimeDataSyncProvider provider)
{
    public Task<CrimeDataSyncOutcome> ExecuteAsync(CancellationToken cancellationToken) =>
        provider.SyncAsync(cancellationToken);
}
