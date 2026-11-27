using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class TieredAlertEscalationDeliveryTests
{
    [Fact]
    public async Task SendsTicketsAndAfterHoursPagesAndRecordsOnlySuccessfulDelivery()
    {
        var now = DateTime.UtcNow;
        var alert = new AiopsAlertEntry(
            1, "Down", "High", "router-a", "10.0.0.1", "Down", null, "details", null,
            "{\"Normalized_Alert_Level\":\"P1-High\"}", "Central NOC", now, null,
            false, false, false, false, null, "Router", "network", null, null, null, null, null);
        var dashboardStore = new StubDashboardStore(alert);
        var facilities = new StubFacilityStore();
        var escalationStore = new StubAutoEscalationStore();
        var sender = new StubEmailSender();
        var settings = new StubIntegrationSettings();
        var dashboard = new AiopsDashboardQueries(
            dashboardStore, new FacilityDirectoryCommands(facilities), new AiopsInvestigationState());
        var commands = new TieredAlertEscalationCommands(
            new StubAnalysisStore(), dashboardStore, new AiopsRcaAnalysisEngine(), dashboard,
            escalationStore, facilities, settings, sender);

        var result = await commands.ExecuteAsync(CancellationToken.None);

        Assert.Equal(1, result.TicketsSent);
        var expectedPages = TieredAlertEscalationCommands.IsBusinessHours(now) ? 0 : 1;
        Assert.Equal(expectedPages, result.PagesSent);
        Assert.Contains(sender.Calls, call => call.Recipient == "tickets@example.test" && call.Subject.Contains("TICKET", StringComparison.Ordinal));
        Assert.Equal(new[] { 1 }, escalationStore.TicketedIds);
        Assert.Equal(expectedPages == 1, escalationStore.PageMarked);
        if (expectedPages == 1)
        {
            Assert.Contains(sender.Calls, call => call.Recipient == "itnetwork@example.test" && call.Subject.Contains("ONPAGE", StringComparison.Ordinal));
            Assert.Contains("SITE CONTACTS (REFERENCE ONLY)", sender.Calls.Single(call => call.Subject.Contains("ONPAGE", StringComparison.Ordinal)).Body);
        }
    }

    private sealed class StubIntegrationSettings : IOperationalIntegrationSettingsStore
    {
        public Task<OperationalIntegrationSettings> GetAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new OperationalIntegrationSettings(
                "", "tickets@example.test", "notify@example.test", "noc@example.test", "itnetwork@example.test",
                "", false, true, "", 15, 500, "", "", new Dictionary<string, string>()));

        public Task<ElasticClientSettings> GetElasticClientSettingsAsync(CancellationToken cancellationToken) =>
            Task.FromResult(new ElasticClientSettings("", "", true, "", 15, 500));

        public Task SaveAsync(OperationalIntegrationSettingsUpdate update, int actorUserId, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class StubAnalysisStore : IAiopsRcaAnalysisStore
    {
        public Task<AiopsRcaAnalysisContext> GetAnalysisContextAsync(
            DateTime nowUtc, DateTime historyCutoffUtc, bool includeHistory, CancellationToken cancellationToken) =>
            Task.FromResult(new AiopsRcaAnalysisContext([], [], [], []));
    }

    private sealed class StubAutoEscalationStore : IAutoEscalationStore
    {
        public IReadOnlyList<int> TicketedIds { get; private set; } = [];
        public bool PageMarked { get; private set; }

        public Task<bool> IsNodeOnCooldownAsync(int alertId, string nodeName, string? siteName, DateTime cooldownCutoffUtc, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<bool> IsNodePagedAsync(string siteName, string? nodeName, int alertId, CancellationToken cancellationToken) =>
            Task.FromResult(false);

        public Task<int> MarkTicketedAsync(IReadOnlyList<int> alertIds, CancellationToken cancellationToken)
        {
            TicketedIds = alertIds;
            return Task.FromResult(alertIds.Count);
        }

        public Task<int> MarkPageSentAsync(string siteName, string? nodeName, int alertId, DateTime sentAtUtc, CancellationToken cancellationToken)
        {
            PageMarked = true;
            return Task.FromResult(1);
        }
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public List<(string Recipient, string Subject, string Body)> Calls { get; } = [];

        public Task<EmailSendResult> SendPlainTextAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken)
        {
            Calls.Add((recipientOverride, subject, body));
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }

        public Task<EmailSendResult> SendHtmlAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            SendPlainTextAsync(recipientOverride, subject, body, cancellationToken);

        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(string recipientOverride, string subject, string body,
            IReadOnlyList<EmailAttachment> attachments, CancellationToken cancellationToken) =>
            SendHtmlAsync(recipientOverride, subject, body, cancellationToken);
    }

    private sealed class StubFacilityStore : IFacilityDirectoryStore
    {
        private static readonly MonitoredLocationEntry Location = new(
            1, "Central NOC", 34.8, -92.2, "NOC", "Central", "P1-Critical", null, null, false,
            null, null, null, null, null, null, null, null);

        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationEntry>>([Location]);
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationEntry>>([Location]);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>([
                new MonitoredLocationContactEntry(1, "NOC Desk", "555-0100", "noc@example.test", 0)]);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(
            int locationId, IReadOnlyList<MonitoredLocationContactValue> contacts, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<int> ImportLocationsAsync(IReadOnlyList<MonitoredLocationImportRow> locations, string mode, CancellationToken cancellationToken) =>
            Task.FromResult(0);
        public Task UpdateLocationsAsync(IReadOnlyList<MonitoredLocationEditRow> locations, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class StubDashboardStore(AiopsAlertEntry alert) : IAiopsDashboardStore
    {
        public Task<IReadOnlyList<AiopsAlertEntry>> GetUnresolvedAlertsAsync(IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AiopsAlertEntry>>([alert]);
        public Task<IReadOnlyList<AiopsAlertEntry>> GetActiveAlertsAsync(IReadOnlySet<string>? allowedSiteNames, DateTime receivedAfterUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AiopsAlertEntry>>([alert]);
        public Task<IReadOnlyList<AiopsTimelineEventEntry>> GetTimelineEventsAsync(IReadOnlySet<string>? allowedSiteNames, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AiopsTimelineEventEntry>>([]);
        public Task<IReadOnlyList<AiopsRegionalOutageEntry>> GetUnresolvedOutagesAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AiopsRegionalOutageEntry>>([]);
        public Task<IReadOnlyDictionary<string, int>> GetActiveIssueCountsAsync(IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyDictionary<string, int>>(new Dictionary<string, int>());
        public Task<bool> AcknowledgeAlertsAsync(IReadOnlyList<int> alertIds, string username, DateTime acknowledgedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> CanAccessAlertIdsAsync(IReadOnlyList<int> alertIds, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SetClusterDispatchAsync(IReadOnlyList<int> alertIds, bool isDispatched, string username, DateTime dispatchedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<AiopsNeedsDispatchUpdate> SetSiteNeedsDispatchAsync(string siteName, bool needsDispatch, string username, DateTime modifiedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(new AiopsNeedsDispatchUpdate(AiopsNeedsDispatchOutcome.Updated, 0));
        public Task<bool> SetSiteMaintenanceAsync(string siteName, bool isMaintenance, DateTime? maintenanceEtr, string? maintenanceReason, string username, DateTime modifiedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<AiopsSiteResolutionUpdate> ResolveSiteAsync(string siteName, string username, DateTime resolvedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(new AiopsSiteResolutionUpdate(AiopsSiteResolutionOutcome.Resolved, 0));
        public Task<bool> ResolveAlertAsync(int alertId, string nodeName, DateTime resolvedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }
}
