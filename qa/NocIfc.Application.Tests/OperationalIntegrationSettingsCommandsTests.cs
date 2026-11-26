using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class OperationalIntegrationSettingsCommandsTests
{
    [Fact]
    public async Task NormalizesRecipientsAndElasticTextBeforeSaving()
    {
        var store = new StubStore();
        var commands = new OperationalIntegrationSettingsCommands(store);
        var update = new OperationalIntegrationSettingsUpdate(
            " Security@example.com; security@example.com, noc@example.com ",
            null, null, null, null,
            " https://elastic.example.com/ ",
            " secret-key ",
            true,
            " /etc/elastic/ca.pem ",
            30,
            1000,
            null,
            null,
            new HashSet<string>(["risk_alert_recipients", "elastic_url", "elastic_api_key", "elastic_verify_certs", "elastic_ca_certs", "elastic_request_timeout", "elastic_max_results"], StringComparer.Ordinal));

        await commands.SaveAsync(update, 7, CancellationToken.None);

        Assert.NotNull(store.Saved);
        Assert.Equal("Security@example.com, security@example.com, noc@example.com", store.Saved.RiskAlertRecipients);
        Assert.Equal("https://elastic.example.com", store.Saved.ElasticUrl);
        Assert.Equal("secret-key", store.Saved.ElasticApiKey);
        Assert.Equal("/etc/elastic/ca.pem", store.Saved.ElasticCaCerts);
        Assert.Equal(7, store.ActorUserId);
    }

    [Fact]
    public async Task PreservesNullAsAnExplicitResetAndRejectsInvalidOverrides()
    {
        var store = new StubStore();
        var commands = new OperationalIntegrationSettingsCommands(store);
        var reset = new OperationalIntegrationSettingsUpdate(
            null, null, null, null, null, null, null, null, null, null, null, null, null,
            new HashSet<string>(["elastic_url"], StringComparer.Ordinal));
        await commands.SaveAsync(reset, 7, CancellationToken.None);
        Assert.Contains("elastic_url", store.Saved!.ProvidedFields);
        Assert.Null(store.Saved.ElasticUrl);

        var invalidRecipients = reset with
        {
            RiskAlertRecipients = "bad-address",
            ProvidedFields = new HashSet<string>(["risk_alert_recipients"], StringComparer.Ordinal),
        };
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(invalidRecipients, 7, CancellationToken.None));

        var credentialUrl = reset with
        {
            ElasticUrl = "https://user:secret@elastic.example.com",
            ProvidedFields = new HashSet<string>(["elastic_url"], StringComparer.Ordinal),
        };
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(credentialUrl, 7, CancellationToken.None));

        var invalidTimeout = reset with
        {
            ElasticRequestTimeout = 0,
            ProvidedFields = new HashSet<string>(["elastic_request_timeout"], StringComparer.Ordinal),
        };
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(invalidTimeout, 7, CancellationToken.None));

        var invalidLimit = reset with
        {
            ElasticMaxResults = 5001,
            ProvidedFields = new HashSet<string>(["elastic_max_results"], StringComparer.Ordinal),
        };
        await Assert.ThrowsAsync<ArgumentException>(() => commands.SaveAsync(invalidLimit, 7, CancellationToken.None));
    }

    private sealed class StubStore : IOperationalIntegrationSettingsStore
    {
        public OperationalIntegrationSettingsUpdate? Saved { get; private set; }
        public int ActorUserId { get; private set; }

        public Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new OperationalIntegrationSettings(
                "", "", "", "", "", "", false, true, "", 15, 500, "", "",
                new Dictionary<string, string>()));

        public Task<ElasticClientSettings> GetElasticClientSettingsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ElasticClientSettings("", "", true, "", 15, 500));

        public Task SaveAsync(
            OperationalIntegrationSettingsUpdate update,
            int actorUserId,
            CancellationToken cancellationToken)
        {
            Saved = update;
            ActorUserId = actorUserId;
            return Task.CompletedTask;
        }
    }
}
