using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Domain.Dashboard;

namespace NocIfc.Application.Features.Dashboard;

public sealed class InternalRiskQueries(IInternalRiskStore snapshots)
{
    public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) =>
        snapshots.GetLatestAsync(cancellationToken);

    public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(
        int days,
        CancellationToken cancellationToken)
    {
        if (days is < 1 or > 365)
        {
            throw new ArgumentOutOfRangeException(nameof(days), "days must be between 1 and 365.");
        }
        return snapshots.GetHistoryAsync(DateTime.UtcNow.AddDays(-days), cancellationToken);
    }
}
