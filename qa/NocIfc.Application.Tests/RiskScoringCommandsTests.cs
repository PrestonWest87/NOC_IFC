using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class RiskScoringCommandsTests
{
    [Fact]
    public async Task RejectsOutOfRangeOverridesAndSavesValidPartialUpdate()
    {
        var store = new StubStore();
        var commands = new RiskScoringCommands(store);

        var invalid = await Assert.ThrowsAsync<ArgumentException>(() => commands.UpdateAsync(
            new RiskScoringSettings(null, 5.1, null, null, null, null, null, null, null, null, null, null, null),
            CancellationToken.None));
        Assert.Contains("baseline_override_cyber", invalid.Message);
        Assert.Null(store.LastUpdate);

        var valid = new RiskScoringSettings("hybrid", 4.5, null, null, 3, null, null, null, null, -2, null, 2, null);
        await commands.UpdateAsync(valid, CancellationToken.None);

        Assert.Equal(valid, store.LastUpdate);
    }

    [Fact]
    public async Task RequiresAtLeastOneScoringField()
    {
        var commands = new RiskScoringCommands(new StubStore());
        await Assert.ThrowsAsync<ArgumentException>(() => commands.UpdateAsync(
            new RiskScoringSettings(null, null, null, null, null, null, null, null, null, null, null, null, null),
            CancellationToken.None));
    }

    private sealed class StubStore : IRiskScoringSettingsStore
    {
        public RiskScoringSettings? LastUpdate { get; private set; }
        public Task<RiskScoringSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<RiskScoringSettings?>(null);
        public Task UpdateAsync(RiskScoringSettings settings, CancellationToken cancellationToken)
        {
            LastUpdate = settings;
            return Task.CompletedTask;
        }
    }
}
