using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface ICisaKevCatalogProvider
{
    Task<IReadOnlyList<CisaKevEntry>> FetchAsync(CancellationToken cancellationToken);
}
