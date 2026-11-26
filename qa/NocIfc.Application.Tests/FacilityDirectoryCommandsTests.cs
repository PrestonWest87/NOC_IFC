using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class FacilityDirectoryCommandsTests
{
    [Fact]
    public async Task ScopesLocationReadsAndNormalizesSiteContacts()
    {
        var store = new StubStore();
        var commands = new FacilityDirectoryCommands(store);
        var viewer = new AuthenticatedUser(4, "viewer", "analyst", [], [], ["NOC"]);
        var visible = await commands.GetLocationsAsync(viewer, CancellationToken.None);
        var all = await commands.GetLocationsAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []), CancellationToken.None);
        Assert.Single(visible);
        Assert.Equal("NOC", visible[0].LocationType);
        Assert.Equal(2, all.Count);

        var contacts = await commands.ReplaceSiteContactsAsync(
            1,
            [
                new(" Alice ", " +1 (501) 555-0100 ext 4 ", " alice@example.com "),
                new(" ", "", null),
            ],
            CancellationToken.None);
        Assert.NotNull(contacts);
        var saved = Assert.Single(contacts);
        Assert.Equal("Alice", saved.Name);
        Assert.Equal("+1 (501) 555-0100 ext 4", saved.Phone);
        Assert.Equal("alice@example.com", saved.Email);
        Assert.Equal(0, saved.SortOrder);
    }

    [Fact]
    public async Task ValidatesContactCountAndImportModeBeforeWriting()
    {
        var store = new StubStore();
        var commands = new FacilityDirectoryCommands(store);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.ReplaceSiteContactsAsync(
            1,
            Enumerable.Repeat(new SiteContactInput("Contact", null, null), 51).ToArray(),
            CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => commands.ReplaceSiteContactsAsync(
            1, [new SiteContactInput("Contact", "555", null)], CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => commands.ImportLocationsAsync([], "append", CancellationToken.None));
        Assert.Equal(0, store.ContactReplaceCalls);
        Assert.Equal(0, store.ImportCalls);
    }

    private sealed class StubStore : IFacilityDirectoryStore
    {
        public int ContactReplaceCalls { get; private set; }
        public int ImportCalls { get; private set; }

        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationEntry>>(
            [
                new(1, "North", 34, -92, "NOC", "Central", "P1", "None", null, false, null, null, null, null, null, null, null, null),
                new(2, "East", 35, -91, "SCADA", "East", "P2", "None", null, false, null, null, null, null, null, null, null, null),
            ]);

        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) =>
            GetLocationsAsync(cancellationToken);

        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>([]);

        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
            int locationId,
            IReadOnlyList<MonitoredLocationContactValue> contacts,
            CancellationToken cancellationToken)
        {
            ContactReplaceCalls++;
            return Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(contacts.Select((contact, index) =>
                new MonitoredLocationContactEntry(index + 1, contact.Name, contact.Phone, contact.Email, index)).ToArray());
        }

        public Task<int> ImportLocationsAsync(
            IReadOnlyList<MonitoredLocationImportRow> locations,
            string mode,
            CancellationToken cancellationToken)
        {
            ImportCalls++;
            return Task.FromResult(locations.Count);
        }

        public Task UpdateLocationsAsync(IReadOnlyList<MonitoredLocationEditRow> locations, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }
}
