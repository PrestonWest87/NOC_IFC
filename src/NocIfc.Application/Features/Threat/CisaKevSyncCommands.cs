using NocIfc.Application.Abstractions.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed record CisaKevSyncResult(int AddedCount);

public sealed class CisaKevSyncCommands(ICisaKevCatalogProvider catalog, ICisaKevStore kev)
{
    public async Task<CisaKevSyncResult> ExecuteAsync(CancellationToken cancellationToken)
    {
        var entries = await catalog.FetchAsync(cancellationToken);
        var added = await kev.InsertMissingAsync(entries, cancellationToken);
        return new CisaKevSyncResult(added);
    }
}
