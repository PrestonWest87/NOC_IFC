using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class ApplicationSettingsCommandsTests
{
    [Fact]
    public async Task HidesFailedLoginRecipientsFromReadersWithoutManagementGrant()
    {
        var store = new StubStore(Settings(), true);
        var commands = new ApplicationSettingsCommands(store);

        var analyst = await commands.GetAsync(new AuthenticatedUser(3, "alice", "analyst", [], [], []), CancellationToken.None);
        var manager = await commands.GetAsync(
            new AuthenticatedUser(1, "admin", "admin", [], [], []),
            CancellationToken.None);

        Assert.Equal("", analyst?.FailedLoginAlertRecipients);
        Assert.Equal("security@example.com", manager?.FailedLoginAlertRecipients);
    }

    [Fact]
    public async Task NormalizesGlobalSettingsAndRequiresRecipientsAndReadySenderWhenEnablingAlerts()
    {
        var store = new StubStore(Settings() with { FailedLoginAlertEnabled = false, FailedLoginAlertRecipients = "" }, true);
        var commands = new ApplicationSettingsCommands(store);
        var update = new GlobalApplicationSettingsUpdate(
            " https://noc.example.com/ ",
            "Technology stack",
            "AS1, AS2",
            true,
            " Security@example.com; security@example.com, noc@example.com ",
            3,
            10);

        await commands.SaveAsync(update, CancellationToken.None);

        Assert.NotNull(store.Saved);
        Assert.Equal("https://noc.example.com", store.Saved.PublicAppUrl);
        Assert.Equal("Security@example.com, noc@example.com", store.Saved.FailedLoginAlertRecipients);

        var noRecipients = await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(
            update with { FailedLoginAlertRecipients = "" }, CancellationToken.None));
        Assert.Contains("recipient", noRecipients.Message);

        store.EmailReady = false;
        var noSender = await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(update, CancellationToken.None));
        Assert.Contains("active SMTP profile", noSender.Message);
    }

    private static GlobalApplicationSettings Settings() =>
        new("http://localhost:8503", "", "", true, "security@example.com", 5, 5);

    private sealed class StubStore(GlobalApplicationSettings? current, bool emailReady) : IApplicationSettingsStore
    {
        public GlobalApplicationSettingsUpdate? Saved { get; private set; }
        public bool EmailReady { get; set; } = emailReady;

        public Task<GlobalApplicationSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult(current);

        public Task<bool> ActiveEmailProfileIsReadyAsync(CancellationToken cancellationToken) => Task.FromResult(EmailReady);

        public Task SaveAsync(GlobalApplicationSettingsUpdate settings, CancellationToken cancellationToken)
        {
            Saved = settings;
            return Task.CompletedTask;
        }
    }
}
