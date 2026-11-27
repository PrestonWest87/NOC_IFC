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

public sealed class AiopsTicketCommandsTests
{
    [Fact]
    public async Task RejectsOutOfScopeSiteOrAlertsBeforeEmailDelivery()
    {
        var store = new StubDashboardStore { CanAccessAlerts = false };
        var sender = new StubEmailSender(new EmailSendResult(true, "sent"));
        var commands = Commands(store, sender);
        var user = Operator();

        var deniedSite = await commands.SendAsync(user, Ticket("Field Office", [1]), CancellationToken.None);
        var deniedAlert = await commands.SendAsync(user, Ticket("Central NOC", [1, 3]), CancellationToken.None);

        Assert.Equal(AiopsTicketScopeFailure.Site, deniedSite.ScopeFailure);
        Assert.Equal(AiopsTicketScopeFailure.Alerts, deniedAlert.ScopeFailure);
        Assert.Empty(sender.Calls);
        Assert.Equal(0, store.DispatchCalls);
    }

    [Fact]
    public async Task MarksAlertsDispatchedOnlyAfterSuccessfulPlainTextDelivery()
    {
        var store = new StubDashboardStore { CanAccessAlerts = true };
        var sender = new StubEmailSender(new EmailSendResult(false, "SMTP is disabled in Settings."));
        var commands = Commands(store, sender);
        var user = Operator();
        var ticket = Ticket("Central NOC", [1, 2]);

        var failed = await commands.SendAsync(user, ticket, CancellationToken.None);

        Assert.Equal(AiopsTicketScopeFailure.None, failed.ScopeFailure);
        Assert.False(failed.Delivery!.Success);
        Assert.Equal(0, store.DispatchCalls);

        sender.Result = new EmailSendResult(true, "Email sent successfully.");
        var sent = await commands.SendAsync(user, ticket, CancellationToken.None);

        Assert.True(sent.Delivery!.Success);
        var call = Assert.Single(sender.Calls.Skip(1));
        Assert.Equal("dispatch@example.test", call.Recipient);
        Assert.Equal("TICKET: P1 - HIGH Incident at Central NOC", call.Subject);
        Assert.Equal("*** MANUAL TICKET ***\nTarget SLA: 1 Hour\n\nTicket body", call.Body);
        Assert.Equal(1, store.DispatchCalls);
        Assert.Equal("operator", store.DispatchedBy);
        Assert.Equal(new[] { 1, 2 }, store.DispatchedIds);
    }

    private static AiopsTicketCommands Commands(StubDashboardStore store, StubEmailSender sender) =>
        new(new FacilityDirectoryCommands(new StubFacilityStore()), store, sender);

    private static AuthenticatedUser Operator() =>
        new(1, "operator", "analyst", ["AIOps RCA"], ["Action: Dispatch RCA Tickets"], ["NOC"]);

    private static AiopsManualTicket Ticket(string site, IReadOnlyList<int> ids) =>
        new(site, "P1 - HIGH", "Ticket body", "dispatch@example.test", ids, "1 Hour");

    private sealed class StubEmailSender(EmailSendResult result) : IEmailSender
    {
        public EmailSendResult Result { get; set; } = result;
        public List<(string Recipient, string Subject, string Body)> Calls { get; } = [];

        public Task<EmailSendResult> SendPlainTextAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken)
        {
            Calls.Add((recipientOverride, subject, body));
            return Task.FromResult(Result);
        }

        public Task<EmailSendResult> SendHtmlAsync(
            string recipientOverride,
            string subject,
            string body,
            CancellationToken cancellationToken) =>
            SendPlainTextAsync(recipientOverride, subject, body, cancellationToken);

        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride,
            string subject,
            string body,
            IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken) =>
            SendHtmlAsync(recipientOverride, subject, body, cancellationToken);
    }

    private sealed class StubDashboardStore : IAiopsDashboardStore
    {
        public bool CanAccessAlerts { get; init; }
        public int DispatchCalls { get; private set; }
        public string? DispatchedBy { get; private set; }
        public IReadOnlyList<int> DispatchedIds { get; private set; } = [];

        public Task<IReadOnlyList<AiopsAlertEntry>> GetUnresolvedAlertsAsync(IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<AiopsAlertEntry>>([]);
        public Task<IReadOnlyList<AiopsTimelineEventEntry>> GetTimelineEventsAsync(IReadOnlySet<string>? allowedSiteNames, int limit, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<AiopsTimelineEventEntry>>([]);
        public Task<IReadOnlyList<AiopsRegionalOutageEntry>> GetUnresolvedOutagesAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<AiopsRegionalOutageEntry>>([]);
        public Task<IReadOnlyDictionary<string, int>> GetActiveIssueCountsAsync(IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyDictionary<string, int>>(new Dictionary<string, int>());
        public Task<bool> AcknowledgeAlertsAsync(IReadOnlyList<int> alertIds, string username, DateTime acknowledgedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<bool> CanAccessAlertIdsAsync(IReadOnlyList<int> alertIds, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult(CanAccessAlerts);
        public Task<bool> SetClusterDispatchAsync(IReadOnlyList<int> alertIds, bool isDispatched, string username, DateTime dispatchedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken)
        {
            DispatchCalls++;
            DispatchedBy = username;
            DispatchedIds = alertIds;
            return Task.FromResult(true);
        }
        public Task<AiopsNeedsDispatchUpdate> SetSiteNeedsDispatchAsync(string siteName, bool needsDispatch, string username, DateTime modifiedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult(new AiopsNeedsDispatchUpdate(AiopsNeedsDispatchOutcome.Updated, 0));
        public Task<bool> SetSiteMaintenanceAsync(string siteName, bool isMaintenance, DateTime? maintenanceEtr, string? maintenanceReason, string username, DateTime modifiedAtUtc, CancellationToken cancellationToken) => Task.FromResult(true);
        public Task<AiopsSiteResolutionUpdate> ResolveSiteAsync(string siteName, string username, DateTime resolvedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult(new AiopsSiteResolutionUpdate(AiopsSiteResolutionOutcome.Resolved, 0));
        public Task<bool> ResolveAlertAsync(int alertId, string nodeName, DateTime resolvedAtUtc, IReadOnlySet<string>? allowedSiteNames, CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class StubFacilityStore : IFacilityDirectoryStore
    {
        private static readonly IReadOnlyList<MonitoredLocationEntry> Locations =
        [new(1, "Central NOC", 34.8, -92.2, "NOC", "Central", "P1-Critical", null, null, false, null, null, null, null, null, null, null, null)];

        public Task<IReadOnlyList<MonitoredLocationEntry>> GetLocationsAsync(CancellationToken cancellationToken) => Task.FromResult(Locations);
        public Task<IReadOnlyList<MonitoredLocationEntry>> GetAdminLocationsAsync(CancellationToken cancellationToken) => Task.FromResult(Locations);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> GetSiteContactsAsync(int locationId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<IReadOnlyList<MonitoredLocationContactEntry>?> ReplaceSiteContactsAsync(int locationId, IReadOnlyList<MonitoredLocationContactValue> contacts, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<MonitoredLocationContactEntry>?>(null);
        public Task<int> ImportLocationsAsync(IReadOnlyList<MonitoredLocationImportRow> locations, string mode, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task UpdateLocationsAsync(IReadOnlyList<MonitoredLocationEditRow> locations, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
