using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SettingsReferenceDirectoryCommandsTests
{
    [Fact]
    public async Task NormalizesAndPersistsOrderedContactDirectories()
    {
        var store = new StubStore();
        var commands = new SettingsReferenceDirectoryCommands(store);

        var fiber = await commands.ReplaceFiberAsync(
        [
            new(" Fiber NOC ", " Carrier One ", " noc@carrier.example ", " +1 (501) 555-0100 ext 8 "),
            new("Field Desk", "Carrier Two", "field@carrier.example", ""),
        ],
            12,
            CancellationToken.None);
        var onpage = await commands.ReplaceOnpageAsync(
        [new(" IT Network ", " ops@example.test ")],
            12,
            CancellationToken.None);

        Assert.Equal("Fiber NOC", fiber[0].Name);
        Assert.Equal("Carrier One", fiber[0].Company);
        Assert.Equal("noc@carrier.example", fiber[0].Email);
        Assert.Equal("+1 (501) 555-0100 ext 8", fiber[0].Phone);
        Assert.Equal(new[] { 0, 1 }, fiber.Select(row => row.SortOrder));
        Assert.Equal("IT Network", onpage[0].Department);
        Assert.Null(fiber[1].Phone);
        Assert.Equal(12, store.ActorUserId);
    }

    [Fact]
    public async Task CsvImportsMergeByNaturalKeyAndPreserveOmittedOptionalFields()
    {
        var store = new StubStore();
        var commands = new SettingsReferenceDirectoryCommands(store);
        await commands.ReplaceFiberAsync(
            [new("Old Name", "Old Carrier", "same@fiber.example", "+1 501 555 0100")],
            1,
            CancellationToken.None);

        var fiber = await commands.ImportFiberAsync(
            "Name,Company,Email,Phone\n\"New Name\",\"Carrier, Inc.\",same@fiber.example,+1 (501) 555-0100 ext 8\nField Desk,Carrier Two,field@fiber.example,\n",
            "merge",
            2,
            CancellationToken.None);
        Assert.Equal((1, 1, 2), (fiber.Added, fiber.Updated, fiber.Rows.Count));
        Assert.Equal("Carrier, Inc.", fiber.Rows[0].Company);
        Assert.Equal("New Name", fiber.Rows[0].Name);

        var preservePhone = await commands.ImportFiberAsync(
            "name,company,email\nUpdated Name,Carrier Updated,same@fiber.example\n",
            "merge",
            2,
            CancellationToken.None);
        Assert.Equal("+1 (501) 555-0100 ext 8", preservePhone.Rows[0].Phone);

        var onpage = await commands.ImportOnpageAsync(
            "Department,Email\nOperations,ops@example.test\nIT Network,it@example.test\n",
            "merge",
            2,
            CancellationToken.None);
        Assert.Equal(2, onpage.Added);
        Assert.Equal(new[] { "Operations", "IT Network" }, onpage.Rows.Select(row => row.Department));
    }

    [Fact]
    public async Task NetworkAssociationsStayReciprocalAndExplicitCsvUnlinkingClearsBothSides()
    {
        var store = new StubStore();
        var commands = new SettingsReferenceDirectoryCommands(store);
        var initial = await commands.ReplaceNetworkOrdersAsync(
        [
            new("Alpha North", "Alpha West", "ALPHA-1", "Alpha Fiber", ["BETA-1"]),
            new("Beta North", "Beta West", "BETA-1", "Beta Fiber", []),
        ],
            1,
            CancellationToken.None);
        Assert.Equal(new[] { "BETA-1" }, initial[0].AssociatedCircuitNetworkOrderIds);
        Assert.Equal(new[] { "ALPHA-1" }, initial[1].AssociatedCircuitNetworkOrderIds);

        var withoutAssociationColumn = await commands.ImportNetworkOrdersAsync(
            "A location,Z location,Circuit/Network Order ID,Company\nUpdated Alpha,Alpha West,ALPHA-1,Alpha Fiber\n",
            "merge",
            2,
            CancellationToken.None);
        Assert.Equal(new[] { "BETA-1" }, withoutAssociationColumn.Rows[0].AssociatedCircuitNetworkOrderIds);
        Assert.Equal(new[] { "ALPHA-1" }, withoutAssociationColumn.Rows[1].AssociatedCircuitNetworkOrderIds);

        var unlinked = await commands.ImportNetworkOrdersAsync(
            "A location,Z location,Circuit/Network Order ID,Company,Associated Circuit/Network Order IDs\nUpdated Alpha,Alpha West,ALPHA-1,Alpha Fiber,\n",
            "merge",
            2,
            CancellationToken.None);
        Assert.Empty(unlinked.Rows[0].AssociatedCircuitNetworkOrderIds);
        Assert.Empty(unlinked.Rows[1].AssociatedCircuitNetworkOrderIds);

        var replaced = await commands.ImportNetworkOrdersAsync(
            "A location,Z location,Circuit/Network Order ID,Company,Associated Circuit/Network Order IDs\nGamma North,Gamma West,GAMMA-1,Gamma Fiber,DELTA-1\nDelta North,Delta West,DELTA-1,Delta Fiber,\n",
            "replace",
            2,
            CancellationToken.None);
        Assert.Equal((2, 0, 2), (replaced.Added, replaced.Updated, replaced.Rows.Count));
        Assert.Equal(new[] { "DELTA-1" }, replaced.Rows[0].AssociatedCircuitNetworkOrderIds);
        Assert.Equal(new[] { "GAMMA-1" }, replaced.Rows[1].AssociatedCircuitNetworkOrderIds);
    }

    [Fact]
    public async Task InvalidContactsCsvAndAssociationsFailBeforeReplacement()
    {
        var store = new StubStore();
        var commands = new SettingsReferenceDirectoryCommands(store);
        var original = await commands.ReplaceFiberAsync(
            [new("Fiber Duty", "FiberCo", "duty@fiber.example", null)], 1, CancellationToken.None);

        await Assert.ThrowsAsync<ArgumentException>(() => commands.ReplaceFiberAsync(
            [new("Duty", "FiberCo", "one@example.test, two@example.test", null)], 2, CancellationToken.None));
        var rowError = await Assert.ThrowsAsync<ArgumentException>(() => commands.ImportFiberAsync(
            "name,company,email,phone\nDuty,FiberCo,not-an-email,\n", "merge", 2, CancellationToken.None));
        Assert.Contains("CSV row 2", rowError.Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ArgumentException>(() => commands.ImportOnpageAsync(
            "department\nOperations\n", "merge", 2, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => commands.ReplaceNetworkOrdersAsync(
            [new("North", "West", "CIR-1", "FiberCo", ["MISSING"])], 2, CancellationToken.None));

        Assert.Equal(original, await commands.GetFiberAsync(CancellationToken.None));
        Assert.Equal(1, store.FiberReplaceCalls);
        Assert.Equal(0, store.NetworkReplaceCalls);
    }

    private sealed class StubStore : ISettingsReferenceDirectoryStore
    {
        public IReadOnlyList<FiberEmailContactEntry> Fiber { get; private set; } = [];
        public IReadOnlyList<OnpageEmailContactEntry> Onpage { get; private set; } = [];
        public IReadOnlyList<NetworkOrderCircuitEntry> NetworkOrders { get; private set; } = [];
        public int ActorUserId { get; private set; }
        public int FiberReplaceCalls { get; private set; }
        public int NetworkReplaceCalls { get; private set; }

        public Task<IReadOnlyList<FiberEmailContactEntry>> GetFiberAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Fiber);

        public Task<IReadOnlyList<FiberEmailContactEntry>> ReplaceFiberAsync(
            IReadOnlyList<FiberEmailContactValue> contacts,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            FiberReplaceCalls++;
            ActorUserId = actorUserId;
            Fiber = contacts.Select((row, index) => new FiberEmailContactEntry(
                index + 1, row.Name, row.Company, row.Email, row.Phone, index)).ToArray();
            return Task.FromResult(Fiber);
        }

        public Task<IReadOnlyList<OnpageEmailContactEntry>> GetOnpageAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Onpage);

        public Task<IReadOnlyList<OnpageEmailContactEntry>> ReplaceOnpageAsync(
            IReadOnlyList<OnpageEmailContactValue> contacts,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            ActorUserId = actorUserId;
            Onpage = contacts.Select((row, index) => new OnpageEmailContactEntry(
                index + 1, row.Department, row.Email, index)).ToArray();
            return Task.FromResult(Onpage);
        }

        public Task<IReadOnlyList<NetworkOrderCircuitEntry>> GetNetworkOrdersAsync(CancellationToken cancellationToken) =>
            Task.FromResult(NetworkOrders);

        public Task<IReadOnlyList<NetworkOrderCircuitEntry>> ReplaceNetworkOrdersAsync(
            IReadOnlyList<NetworkOrderCircuitValue> records,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            NetworkReplaceCalls++;
            ActorUserId = actorUserId;
            NetworkOrders = records.Select((row, index) => new NetworkOrderCircuitEntry(
                index + 1, row.ALocation, row.ZLocation, row.CircuitNetworkOrderId, row.Company,
                row.AssociatedCircuitNetworkOrderIds, index)).ToArray();
            return Task.FromResult(NetworkOrders);
        }
    }
}
