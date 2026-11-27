using NocIfc.Application.Abstractions.Threat;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class CisaKevSyncCommandsTests
{
    [Fact]
    public async Task FetchesCatalogAndPersistsOnlyThroughTheKevStore()
    {
        var entries = new[]
        {
            new CisaKevEntry(0, "CVE-2026-1234", "Vendor", "Product", "Vulnerability", DateTime.UtcNow, "Details", "Action", "2026-12-01"),
        };
        var catalog = new StubCatalog(entries);
        var store = new StubKevStore();

        var result = await new CisaKevSyncCommands(catalog, store).ExecuteAsync(CancellationToken.None);

        Assert.Equal(1, catalog.Calls);
        Assert.Equal(entries, store.Inserted);
        Assert.Equal(3, result.AddedCount);
    }

    private sealed class StubCatalog(IReadOnlyList<CisaKevEntry> entries) : ICisaKevCatalogProvider
    {
        public int Calls { get; private set; }
        public Task<IReadOnlyList<CisaKevEntry>> FetchAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(entries);
        }
    }

    private sealed class StubKevStore : ICisaKevStore
    {
        public IReadOnlyList<CisaKevEntry> Inserted { get; private set; } = [];
        public Task<int> InsertMissingAsync(IReadOnlyList<CisaKevEntry> entries, CancellationToken cancellationToken)
        {
            Inserted = entries;
            return Task.FromResult(3);
        }
        public Task<IReadOnlyList<CisaKevEntry>> GetRecentAsync(int limit, DateTime addedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<CisaKevEntry>>([]);
    }
}
