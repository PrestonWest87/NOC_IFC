using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed class CisaKevQueries(ICisaKevStore kev)
{
    public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(
        int limit,
        int daysBack,
        CancellationToken cancellationToken)
    {
        if (limit is < 1 or > 200)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 200.");
        }
        if (daysBack is < 1 or > 365)
        {
            throw new ArgumentOutOfRangeException(nameof(daysBack), "days_back must be between 1 and 365.");
        }
        return kev.GetRecentAsync(limit, DateTime.UtcNow.AddDays(-daysBack), cancellationToken);
    }
}
