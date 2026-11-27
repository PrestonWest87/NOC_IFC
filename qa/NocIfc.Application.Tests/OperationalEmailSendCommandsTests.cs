using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.OperationalEmail;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.OperationalEmail;
using NocIfc.Domain.Settings;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class OperationalEmailSendCommandsTests
{
    [Fact]
    public async Task PersistsRenderedSnapshotBeforeSendingAndAppliesDefaultSignature()
    {
        var store = new TestEmailStore(
            [new OperationalEmailSignatureEntry(4, "NOC", "Operations Desk", true, true, 1, 1, null, null)]);
        var sender = new TestOperationalEmailSender(envelope =>
        {
            Assert.Single(store.Emails);
            Assert.Single(store.DeliverySnapshots);
            Assert.Contains("PLANNED MAINTENANCE NOTIFICATION", envelope.TextBody, StringComparison.Ordinal);
            Assert.Contains("--\nOperations Desk", envelope.TextBody, StringComparison.Ordinal);
            return new EmailSendResult(true, "Email sent successfully.");
        });
        var command = CreateCommand(store, sender);
        var input = new OperationalEmailSendInput(
            "maintenance_notice",
            "ops@example.com",
            null,
            null,
            null,
            null,
            new Dictionary<string, string>
            {
                ["ticket_title"] = "Switch upgrade",
                ["site"] = "North facility",
                ["work_scope"] = "Replace the core switch",
                ["start_time"] = "2026-11-28T08:30",
                ["end_time"] = "2026-11-28T10:30",
                ["impact"] = "Medium",
                ["disruption"] = "Potentially Disruptive",
                ["change_department"] = "IT Network",
            },
            [], null, null, null, true,
            new HashSet<string>(["template_key", "to", "fields"], StringComparer.Ordinal));

        var result = await command.SendAsync(input, 7, CancellationToken.None);

        Assert.Equal("sent", result.Status);
        Assert.Equal(1, result.EmailId);
        Assert.Equal(["ops@example.com"], sender.Envelopes.Single().ToRecipients);
        Assert.Contains("11/28/26 08:30 AM", sender.Envelopes.Single().TextBody, StringComparison.Ordinal);
        Assert.Equal(4, store.Emails.Single().SignatureId);
        Assert.Equal("sent", store.CompletedDeliveries.Single().Status);
    }

    [Fact]
    public async Task MorningReportUsesLatestShiftAnalysisAndStoresSanitizedAttachment()
    {
        var store = new TestEmailStore([]);
        var sender = new TestOperationalEmailSender(_ => new EmailSendResult(true, "sent"));
        var command = CreateCommand(store, sender, "Latest dashboard shift handoff");
        var attachment = Convert.ToBase64String([1, 2, 3]);
        var input = new OperationalEmailSendInput(
            "morning_report", "ops@example.com", null, null, null, null, new Dictionary<string, string>(),
            [new OperationalEmailAttachmentInput("C:\\reports\\shift.txt", "text/plain", attachment)],
            null, null, null, false, new HashSet<string>(["template_key", "to", "attachments"], StringComparer.Ordinal));

        var result = await command.SendAsync(input, 7, CancellationToken.None);

        Assert.Equal("sent", result.Status);
        Assert.Equal("Latest dashboard shift handoff", store.Emails.Single().Body);
        var savedAttachment = Assert.Single(store.Emails.Single().Attachments);
        Assert.Equal("shift.txt", savedAttachment.FileName);
        Assert.Equal(new byte[] { 1, 2, 3 }, savedAttachment.Content);
        Assert.Equal(savedAttachment.Content, sender.Envelopes.Single().Attachments.Single().Content);
    }

    [Fact]
    public async Task FiberMaintenanceSendsCompanyScopedCircuitSnapshots()
    {
        var store = new TestEmailStore([]);
        var sender = new TestOperationalEmailSender(_ => new EmailSendResult(true, "sent"));
        var directories = new TestDirectories
        {
            Fiber =
            [
                new FiberEmailContactEntry(1, "Provider A Ops", "Provider A", "a@example.com", null, 0),
                new FiberEmailContactEntry(2, "Provider B Ops", "Provider B", "b@example.com", null, 1),
            ],
            NetworkOrders =
            [
                new NetworkOrderCircuitEntry(10, "A-side", "Z-side", "CIR-A", "Provider A", [], 0),
                new NetworkOrderCircuitEntry(11, "West", "East", "CIR-B", "Provider B", [], 1),
            ],
        };
        var command = CreateCommand(store, sender, directories: directories);
        var input = new OperationalEmailSendInput(
            "fiber_maintenance_notice", null, null, null, null, null,
            new Dictionary<string, string>
            {
                ["ticket_title"] = "Fiber splice",
                ["network_order_ids"] = "10, 11",
                ["work_scope"] = "Splice both routes",
                ["start_time"] = "2026-11-28T08:30",
                ["end_time"] = "2026-11-28T10:30",
                ["impact"] = "Low",
                ["disruption"] = "Non-Disruptive",
            }, [], null, null, null, true,
            new HashSet<string>(["template_key", "fields"], StringComparer.Ordinal));

        var result = await command.SendAsync(input, 7, CancellationToken.None);

        Assert.True(result.Grouped);
        Assert.Equal(2, result.CompanyCount);
        Assert.Equal(2, sender.Envelopes.Count);
        Assert.Equal("a@example.com", sender.Envelopes[0].ToRecipients.Single());
        Assert.Equal("b@example.com", sender.Envelopes[1].ToRecipients.Single());
        Assert.Contains("CIR-A", sender.Envelopes[0].TextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("CIR-B", sender.Envelopes[0].TextBody, StringComparison.Ordinal);
        Assert.Contains("CIR-B", sender.Envelopes[1].TextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("CIR-A", sender.Envelopes[1].TextBody, StringComparison.Ordinal);
        Assert.All(store.Emails, email => Assert.Equal("noc@example.com", Assert.Single(email.CcRecipients)));
    }

    [Fact]
    public async Task RejectsVisibleBccOverlapBeforeCreatingAnySnapshot()
    {
        var store = new TestEmailStore([]);
        var sender = new TestOperationalEmailSender(_ => throw new InvalidOperationException("Should not send."));
        var command = CreateCommand(store, sender);
        var input = new OperationalEmailSendInput(
            "maintenance_notice", "ops@example.com", null, "ops@example.com", null, null,
            new Dictionary<string, string>
            {
                ["ticket_title"] = "Switch upgrade",
                ["site"] = "North facility",
                ["work_scope"] = "Replace the core switch",
                ["start_time"] = "2026-11-28T08:30",
                ["end_time"] = "2026-11-28T10:30",
                ["impact"] = "Medium",
                ["disruption"] = "Potentially Disruptive",
                ["change_department"] = "IT Network",
            }, [], null, null, null, false,
            new HashSet<string>(["template_key", "to", "bcc", "fields"], StringComparer.Ordinal));

        var error = await Assert.ThrowsAsync<ArgumentException>(
            () => command.SendAsync(input, 7, CancellationToken.None));

        Assert.Contains("both a visible field and BCC", error.Message, StringComparison.Ordinal);
        Assert.Empty(store.Emails);
        Assert.Empty(sender.Envelopes);
    }

    [Fact]
    public async Task FiberFollowupInheritsOnlyItsSuccessfullySentCompanySource()
    {
        var store = new TestEmailStore([])
        {
            SourceMessages =
            [
                new OperationalEmailSourceMessage(
                    100, "fiber_outage", "source-group", "Provider A", false,
                    "FIBER OUTAGE — North", "Source message",
                    new Dictionary<string, string>
                    {
                        ["site"] = "North",
                        ["network_orders"] = "CIR-A",
                        ["contact"] = "Carrier desk",
                        ["outage_start"] = "11/28/26 08:30 AM",
                        ["impact"] = "Primary route unavailable",
                        ["reference"] = "INC-12",
                    },
                    ["carrier-a@example.com"], ["noc@example.com"], ["fiber-a@example.com"],
                    null, null, null),
            ],
        };
        var sender = new TestOperationalEmailSender(_ => new EmailSendResult(true, "sent"));
        var directories = new TestDirectories
        {
            Fiber =
            [
                new FiberEmailContactEntry(1, "Carrier A", "Provider A", "carrier-a@example.com", null, 0),
                new FiberEmailContactEntry(2, "Fiber A", "Provider A", "fiber-a@example.com", null, 1),
            ],
        };
        var command = CreateCommand(store, sender, directories: directories);
        var input = new OperationalEmailSendInput(
            "fiber_outage_update", null, null, null, null, null,
            new Dictionary<string, string>
            {
                ["update_time"] = "2026-11-28T09:30",
                ["update_details"] = "Carrier is replacing the damaged section.",
            }, [], null, 100, null, true,
            new HashSet<string>(["template_key", "source_email_id", "fields"], StringComparer.Ordinal));

        var result = await command.SendAsync(input, 7, CancellationToken.None);

        Assert.Equal("sent", result.Status);
        Assert.True(result.Grouped);
        Assert.Equal("carrier-a@example.com", sender.Envelopes.Single().ToRecipients.Single());
        Assert.Equal("fiber-a@example.com", sender.Envelopes.Single().BccRecipients.Single());
        Assert.Equal(100, store.Emails.Single().ParentEmailId);
        Assert.Equal("Provider A", store.Emails.Single().GroupCompany);
        Assert.Contains("Carrier is replacing the damaged section.", store.Emails.Single().Body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GroupedFiberOutageCollapsesUnmatchedBccToOneCircuitFreeCopy()
    {
        var store = new TestEmailStore([]);
        var sender = new TestOperationalEmailSender(_ => new EmailSendResult(true, "sent"));
        var directories = new TestDirectories
        {
            Fiber =
            [
                new FiberEmailContactEntry(1, "Provider A", "Provider A", "a@example.com", null, 0),
                new FiberEmailContactEntry(2, "Provider B", "Provider B", "b@example.com", null, 1),
            ],
            NetworkOrders =
            [
                new NetworkOrderCircuitEntry(10, "A-side", "Z-side", "CIR-A", "Provider A", [], 0),
                new NetworkOrderCircuitEntry(11, "West", "East", "CIR-B", "Provider B", [], 1),
            ],
        };
        var command = CreateCommand(store, sender, directories: directories);
        var input = new OperationalEmailSendInput(
            "fiber_outage", "", null, "archive@example.com", null, null,
            new Dictionary<string, string>
            {
                ["site"] = "North route",
                ["network_order_ids"] = "10, 11",
                ["outage_start"] = "2026-11-28T08:30",
                ["impact"] = "Primary route unavailable",
            }, [], null, null, null, true,
            new HashSet<string>(["template_key", "to", "bcc", "fields"], StringComparer.Ordinal));

        var result = await command.SendAsync(input, 7, CancellationToken.None);

        Assert.Equal("sent", result.Status);
        Assert.True(result.Grouped);
        Assert.Equal(2, result.CompanyCount);
        Assert.Equal(3, store.Emails.Count);
        var bccCopy = Assert.Single(result.BccCopyDeliveries!);
        Assert.Equal("archive@example.com", sender.Envelopes.Single(envelope => envelope.BccRecipients.Contains("archive@example.com")).BccRecipients.Single());
        Assert.Equal("noc@example.com", sender.Envelopes.Single(envelope => envelope.BccRecipients.Contains("archive@example.com")).ToRecipients.Single());
        Assert.DoesNotContain("CIR-A", sender.Envelopes.Single(envelope => envelope.BccRecipients.Contains("archive@example.com")).TextBody, StringComparison.Ordinal);
        Assert.DoesNotContain("CIR-B", sender.Envelopes.Single(envelope => envelope.BccRecipients.Contains("archive@example.com")).TextBody, StringComparison.Ordinal);
        Assert.Null(bccCopy.Company);
    }

    private static OperationalEmailSendCommands CreateCommand(
        TestEmailStore store,
        TestOperationalEmailSender sender,
        string latestShift = "",
        TestDirectories? directories = null) => new(
            store,
            directories ?? new TestDirectories(),
            new TestSmtpSettings(),
            new TestDashboardStore(latestShift),
            sender);

    private sealed class TestOperationalEmailSender(Func<OperationalEmailEnvelope, EmailSendResult> send)
        : IOperationalEmailSender
    {
        public List<OperationalEmailEnvelope> Envelopes { get; } = [];

        public Task<EmailSendResult> SendOperationalEmailAsync(
            OperationalEmailEnvelope envelope,
            CancellationToken cancellationToken)
        {
            Envelopes.Add(envelope);
            return Task.FromResult(send(envelope));
        }
    }

    private sealed class TestEmailStore(IReadOnlyList<OperationalEmailSignatureEntry> signatures)
        : IOperationalEmailStore
    {
        private readonly Dictionary<string, OperationalEmailTemplateDefault> templates = new(StringComparer.Ordinal);
        private int nextEmailId = 1;
        private int nextDeliveryId = 1;

        public List<OperationalEmailMessageSnapshot> Emails { get; } = [];
        public List<int> DeliverySnapshots { get; } = [];
        public List<(int EmailId, string Status)> CompletedDeliveries { get; } = [];
        public IReadOnlyList<OperationalEmailSourceMessage> SourceMessages { get; init; } = [];

        public Task EnsureTemplateDefaultsAsync(
            IReadOnlyList<OperationalEmailTemplateDefault> defaults,
            CancellationToken cancellationToken)
        {
            foreach (var item in defaults) templates.TryAdd(item.TemplateKey, item);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<OperationalEmailTemplateDefault>> GetTemplateDefaultsAsync(
            CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<OperationalEmailTemplateDefault>>(templates.Values.ToArray());

        public Task<bool> UpdateTemplateDefaultsAsync(
            string templateKey,
            IReadOnlyDictionary<string, string> values,
            int actorUserId,
            CancellationToken cancellationToken) => Task.FromResult(false);

        public Task<IReadOnlyList<OperationalEmailSignatureEntry>> GetSignaturesAsync(
            bool includeInactive,
            CancellationToken cancellationToken) => Task.FromResult(signatures);

        public Task<OperationalEmailSignatureEntry?> GetSignatureAsync(int signatureId, CancellationToken cancellationToken) =>
            Task.FromResult(signatures.FirstOrDefault(signature => signature.Id == signatureId));

        public Task<OperationalEmailSignatureMutation> CreateSignatureAsync(
            OperationalEmailSignatureValues signature,
            int actorUserId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<OperationalEmailSignatureMutation> UpdateSignatureAsync(
            int signatureId,
            OperationalEmailSignatureValues signature,
            IReadOnlyList<string> changedFields,
            int actorUserId,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<int> CreateEmailAsync(OperationalEmailMessageSnapshot email, CancellationToken cancellationToken)
        {
            Emails.Add(email);
            return Task.FromResult(nextEmailId++);
        }

        public Task<int> CreateDeliverySnapshotAsync(
            int emailId,
            string smtpProvider,
            string? senderAddress,
            DateTime attemptedAtUtc,
            CancellationToken cancellationToken)
        {
            Assert.InRange(emailId, 1, Emails.Count);
            DeliverySnapshots.Add(emailId);
            return Task.FromResult(nextDeliveryId++);
        }

        public Task CompleteImmediateDeliveryAsync(
            int emailId,
            int deliveryId,
            bool success,
            string message,
            DateTime completedAtUtc,
            CancellationToken cancellationToken)
        {
            CompletedDeliveries.Add((emailId, success ? "sent" : "failed"));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<OperationalEmailSourceMessage>> GetSuccessfulSourceMessagesAsync(
            int sourceEmailId,
            IReadOnlyList<string> allowedTemplateKeys,
            bool includeBccCopies,
            CancellationToken cancellationToken) =>
            Task.FromResult(SourceMessages);
    }

    private sealed class TestDirectories : ISettingsReferenceDirectoryStore
    {
        public IReadOnlyList<FiberEmailContactEntry> Fiber { get; init; } = [];
        public IReadOnlyList<OnpageEmailContactEntry> Onpage { get; init; } = [];
        public IReadOnlyList<NetworkOrderCircuitEntry> NetworkOrders { get; init; } = [];

        public Task<IReadOnlyList<FiberEmailContactEntry>> GetFiberAsync(CancellationToken cancellationToken) => Task.FromResult(Fiber);
        public Task<IReadOnlyList<OnpageEmailContactEntry>> GetOnpageAsync(CancellationToken cancellationToken) => Task.FromResult(Onpage);
        public Task<IReadOnlyList<NetworkOrderCircuitEntry>> GetNetworkOrdersAsync(CancellationToken cancellationToken) => Task.FromResult(NetworkOrders);
        public Task<IReadOnlyList<FiberEmailContactEntry>> ReplaceFiberAsync(IReadOnlyList<FiberEmailContactValue> contacts, int actorUserId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<OnpageEmailContactEntry>> ReplaceOnpageAsync(IReadOnlyList<OnpageEmailContactValue> contacts, int actorUserId, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<NetworkOrderCircuitEntry>> ReplaceNetworkOrdersAsync(IReadOnlyList<NetworkOrderCircuitValue> records, int actorUserId, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class TestSmtpSettings : IAiSmtpSettingsStore
    {
        private static readonly AiSmtpSettings Value = new(
            null, "openai_compatible", false, null, null, null,
            "smtp", true, "smtp.example.com", 587, null, "noc@example.com", null, false,
            false, "", "", false, false, false);

        public Task<AiSmtpSettings?> GetAsync(CancellationToken cancellationToken) => Task.FromResult<AiSmtpSettings?>(Value);
        public Task<string> GetSavedLlmApiKeyForProviderAsync(string provider, CancellationToken cancellationToken) => Task.FromResult("");
        public Task SaveAsync(AiSmtpSettingsUpdate update, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class TestDashboardStore(string rollingSummary) : IOperationalDashboardStore
    {
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<DashboardBriefSnapshot?>(new DashboardBriefSnapshot(rollingSummary, null, null, null, null, null, null, null));
        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
