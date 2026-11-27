using NocIfc.Domain.Dashboard;

namespace NocIfc.Application.Abstractions.Dashboard;

public interface IInternalRiskStore
{
    Task<InternalRiskAssetInventory> GetAssetInventoryAsync(CancellationToken cancellationToken);
    Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(
        DateTime sinceUtc,
        CancellationToken cancellationToken);
    Task SaveSnapshotAsync(InternalRiskSnapshotEntry snapshot, CancellationToken cancellationToken);
}
