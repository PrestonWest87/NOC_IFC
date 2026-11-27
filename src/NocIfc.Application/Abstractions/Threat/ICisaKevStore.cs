using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface ICisaKevStore
{
    Task<int> InsertMissingAsync(IReadOnlyList<CisaKevEntry> entries, CancellationToken cancellationToken);
    Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(
        int limit,
        DateTime addedAfterUtc,
        CancellationToken cancellationToken);
}
