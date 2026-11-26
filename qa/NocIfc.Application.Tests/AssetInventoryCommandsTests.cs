using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class AssetInventoryCommandsTests
{
    [Fact]
    public async Task ParsesSoftwareAndHardwareCsvWithSupportedHeadersAndNumericValues()
    {
        var store = new StubStore();
        var commands = new AssetInventoryCommands(store);

        var software = await commands.ImportSoftwareCsvAsync(
            "Name,Version\n\"Router, Edge\",1\nSwitch OS,2\n", CancellationToken.None);
        Assert.True(software.Success);
        Assert.Equal("Imported 2 software assets.", software.Message);
        Assert.Equal(new[] { "Router, Edge", "Switch OS" }, store.SoftwareNames);

        var hardware = await commands.ImportHardwareCsvAsync(
            "IP Address,Asset Name,Instances,Risk Score\n192.0.2.10,Core Router,4,72.5\n",
            CancellationToken.None);
        Assert.True(hardware.Success);
        Assert.Equal("Imported 1 hardware assets.", hardware.Message);
        var row = Assert.Single(store.HardwareRows);
        Assert.Equal("192.0.2.10", row.Values["ip_address"]);
        Assert.Equal("Core Router", row.Values["asset_name"]);
        Assert.Equal(4, row.Values["instances"]);
        Assert.Equal(72.5, row.Values["risk_score"]);
    }

    [Fact]
    public async Task ReportsMissingHeadersAndBadNumericValuesWithoutReplacingInventory()
    {
        var store = new StubStore();
        var commands = new AssetInventoryCommands(store);

        var missingSoftwareHeader = await commands.ImportSoftwareCsvAsync("software\nrouter\n", CancellationToken.None);
        var noSoftwareRows = await commands.ImportSoftwareCsvAsync("name\n\n", CancellationToken.None);
        var missingHardwareHeader = await commands.ImportHardwareCsvAsync("asset name,instances\nRouter,1\n", CancellationToken.None);
        var badHardwareNumber = await commands.ImportHardwareCsvAsync(
            "IP Address,Instances\n192.0.2.10,many\n", CancellationToken.None);

        Assert.False(missingSoftwareHeader.Success);
        Assert.Contains("name", missingSoftwareHeader.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(noSoftwareRows.Success);
        Assert.False(missingHardwareHeader.Success);
        Assert.False(badHardwareNumber.Success);
        Assert.Contains("CSV row 2", badHardwareNumber.Message, StringComparison.Ordinal);
        Assert.Empty(store.SoftwareNames);
        Assert.Empty(store.HardwareRows);
    }

    private sealed class StubStore : IAssetInventoryStore
    {
        public IReadOnlyList<string> SoftwareNames { get; private set; } = [];
        public IReadOnlyList<HardwareAssetImportRow> HardwareRows { get; private set; } = [];

        public Task ReplaceSoftwareAssetsAsync(IReadOnlyList<string> names, CancellationToken cancellationToken)
        {
            SoftwareNames = names;
            return Task.CompletedTask;
        }

        public Task ReplaceHardwareAssetsAsync(
            IReadOnlyList<HardwareAssetImportRow> assets,
            CancellationToken cancellationToken)
        {
            HardwareRows = assets;
            return Task.CompletedTask;
        }
    }
}
