using System.Text.Json.Nodes;
using NocIfc.Application.Abstractions.Regional;
using NocIfc.Application.Features.Regional;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RegionalHazardSyncCommandsTests
{
    [Theory]
    [InlineData("ok")]
    [InlineData("not_modified")]
    [InlineData("throttled")]
    [InlineData("backoff")]
    public async Task AcceptsHealthyOrCentrallyDeferredNwsRefresh(string nwsStatus)
    {
        var commands = new RegionalHazardSyncCommands(new StubProvider(nwsStatus, "ok"));

        var result = await commands.ExecuteAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("ok", result.Body["status"]!.GetValue<string>());
        Assert.Equal(nwsStatus, result.Body["feeds"]!["nws_alerts"]!["status"]!.GetValue<string>());
    }

    [Fact]
    public async Task Returns502DetailShapeForAnyFailedFeedGroup()
    {
        var commands = new RegionalHazardSyncCommands(new StubProvider("error", "partial_failure"));

        var result = await commands.ExecuteAsync(CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal("One or more hazard sources failed to refresh.", result.Body["detail"]!["message"]!.GetValue<string>());
        Assert.Equal("error", result.Body["detail"]!["feeds"]!["nws_alerts"]!["status"]!.GetValue<string>());
        Assert.Equal("partial_failure", result.Body["detail"]!["feeds"]!["regional_hazards"]!["status"]!.GetValue<string>());
    }

    private sealed class StubProvider(string nwsStatus, string regionalStatus) : IRegionalHazardSyncProvider
    {
        public Task<JsonObject> SyncNwsAlertsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new JsonObject { ["status"] = nwsStatus });

        public Task<JsonObject> SyncRegionalFeedsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new JsonObject { ["status"] = regionalStatus });
    }
}
