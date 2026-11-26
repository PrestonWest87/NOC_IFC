using System.Text.Json.Nodes;

namespace NocIfc.Application.Abstractions.Regional;

public interface IRegionalHazardSyncProvider
{
    Task<JsonObject> SyncNwsAlertsAsync(CancellationToken cancellationToken);
    Task<JsonObject> SyncRegionalFeedsAsync(CancellationToken cancellationToken);
}
