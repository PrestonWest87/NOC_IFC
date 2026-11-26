using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Domain.Dashboard;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class InternalRiskQueriesTests
{
    [Fact]
    public async Task AppliesHistoryBoundsAndPassesRequestedWindow()
    {
        var store = new StubStore();
        var queries = new InternalRiskQueries(store);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetHistoryAsync(0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetHistoryAsync(366, CancellationToken.None));
        Assert.Equal(0, store.HistoryCalls);

        await queries.GetHistoryAsync(28, CancellationToken.None);
        Assert.Equal(1, store.HistoryCalls);
        Assert.InRange(store.SinceUtc, DateTime.UtcNow.AddDays(-28).AddSeconds(-2), DateTime.UtcNow.AddDays(-28).AddSeconds(1));
    }

    private sealed class StubStore : IInternalRiskStore
    {
        public int HistoryCalls { get; private set; }
        public DateTime SinceUtc { get; private set; }

        public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) =>
            Task.FromResult<InternalRiskSnapshotEntry?>(null);

        public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(DateTime sinceUtc, CancellationToken cancellationToken)
        {
            HistoryCalls++;
            SinceUtc = sinceUtc;
            return Task.FromResult<IReadOnlyList<InternalRiskHistoryPoint>>([]);
        }
    }
}
