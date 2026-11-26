using NocIfc.Domain.Dashboard;

namespace NocIfc.Application.Abstractions.Dashboard;

public interface IInternalRiskStore
{
    Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(
        DateTime sinceUtc,
        CancellationToken cancellationToken);
}
