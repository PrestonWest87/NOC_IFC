using NocIfc.Domain.Threat;

namespace NocIfc.Application.Abstractions.Threat;

public interface ICisaKevStore
{
    Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(
        int limit,
        DateTime addedAfterUtc,
        CancellationToken cancellationToken);
}
