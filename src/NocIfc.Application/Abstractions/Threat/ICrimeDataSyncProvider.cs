using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface ICrimeDataSyncProvider
{
    Task<CrimeDataSyncOutcome> SyncAsync(CancellationToken cancellationToken);
}
