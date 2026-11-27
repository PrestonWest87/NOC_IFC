using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CisaKevQueriesTests
{
    [Fact]
    public async Task AppliesQueryBoundsBeforeCallingStore()
    {
        var store = new StubStore();
        var queries = new CisaKevQueries(store);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentAsync(0, 30, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentAsync(201, 30, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentAsync(50, 0, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => queries.GetRecentAsync(50, 366, CancellationToken.None));
        Assert.Equal(0, store.Calls);

        await queries.GetRecentAsync(25, 45, CancellationToken.None);
        Assert.Equal(1, store.Calls);
        Assert.Equal(25, store.Limit);
        Assert.InRange(store.AddedAfterUtc, DateTime.UtcNow.AddDays(-45).AddSeconds(-2), DateTime.UtcNow.AddDays(-45).AddSeconds(1));
    }

    private sealed class StubStore : ICisaKevStore
    {
        public int Calls { get; private set; }
        public int Limit { get; private set; }
        public DateTime AddedAfterUtc { get; private set; }

        public Task<int> InsertMissingAsync(IReadOnlyList<CisaKevEntry> entries, CancellationToken cancellationToken) =>
            Task.FromResult(0);

        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(
            int limit,
            DateTime addedAfterUtc,
            CancellationToken cancellationToken)
        {
            Calls++;
            Limit = limit;
            AddedAfterUtc = addedAfterUtc;
            return Task.FromResult<IReadOnlyList<CisaKevEntry>>([]);
        }
    }
}
