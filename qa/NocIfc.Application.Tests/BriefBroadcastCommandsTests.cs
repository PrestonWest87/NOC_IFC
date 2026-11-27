using System.Text.Json;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Email;
using NocIfc.Domain.Dashboard;
using NocIfc.Domain.Threat;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class BriefBroadcastCommandsTests
{
    [Fact]
    public async Task BroadcastsSavedUnifiedBriefWithCurrentRiskBadgesAndEscapedMarkdown()
    {
        const string content = "---\n**OSINT CORRELATION DISCLAIMER:** External claims.\n\n**AI-GENERATED CONTENT:** Not human reviewed.\n---\n\n## Executive Assessment\n<script>alert(1)</script>";
        var dashboard = new StubDashboardStore(Snapshot(content, "BLUE", "YELLOW"));
        var sender = new StubEmailSender();
        var command = new BriefBroadcastCommands(dashboard, new StubInternalRiskStore(Risk("RED")), sender);

        var result = await command.BroadcastUnifiedAsync("ops@example.test", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("ops@example.test", sender.Recipient);
        Assert.Equal("Executive Unified Risk Brief", sender.Subject);
        Assert.Contains("Unified Posture", sender.Body);
        Assert.Contains("GUARDED", sender.Body);
        Assert.Contains("SEVERE", sender.Body);
        Assert.Contains("External claims.", sender.Body);
        Assert.Contains("Not human reviewed.", sender.Body);
        Assert.Contains("&lt;script&gt;alert(1)&lt;/script&gt;", sender.Body);
        Assert.DoesNotContain("<script>", sender.Body);
    }

    [Fact]
    public async Task ReturnsMissingBriefAndRecipientErrorsWithoutSending()
    {
        var sender = new StubEmailSender();
        var command = new BriefBroadcastCommands(
            new StubDashboardStore(Snapshot(null, "GREEN", "GREEN")),
            new StubInternalRiskStore(null),
            sender);

        var missingRecipient = await command.BroadcastUnifiedAsync("", CancellationToken.None);
        var missingBrief = await command.BroadcastUnifiedAsync("ops@example.test", CancellationToken.None);

        Assert.Equal("No recipient email specified.", missingRecipient.Message);
        Assert.Equal("No unified brief available. Generate one first.", missingBrief.Message);
        Assert.Null(sender.Recipient);
    }

    [Fact]
    public async Task BroadcastsGlobalAndCompleteInternalBriefsButRejectsFailureNotices()
    {
        var dashboard = new StubDashboardStore(Snapshot(
            "## Unified",
            "BLUE",
            "YELLOW",
            globalBrief: "## US CI Assessment\nExternal threat reporting.",
            internalBrief: "## Asset Exposure\nCurrent internal findings."));
        var sender = new StubEmailSender();
        var command = new BriefBroadcastCommands(dashboard, new StubInternalRiskStore(Risk("RED")), sender);

        var global = await command.BroadcastGlobalAsync("ops@example.test", CancellationToken.None);
        var internalBrief = await command.BroadcastInternalAsync("ops@example.test", CancellationToken.None);
        var failedInternal = await new BriefBroadcastCommands(
                new StubDashboardStore(Snapshot("", "BLUE", "RED", internalBrief: "AI failed to process batch.")),
                new StubInternalRiskStore(null),
                sender)
            .BroadcastInternalAsync("ops@example.test", CancellationToken.None);

        Assert.True(global.Success);
        Assert.True(internalBrief.Success);
        Assert.Contains("Global Threat Posture", sender.HtmlCalls[0].Body);
        Assert.Contains("Global Threat Brief — US CI &amp; International", sender.HtmlCalls[0].Body);
        Assert.Equal("Global Threat Brief - US Critical Infrastructure", sender.HtmlCalls[0].Subject);
        Assert.Contains("Internal Asset Risk Brief", sender.HtmlCalls[1].Body);
        Assert.Equal("Internal Asset Risk Brief", sender.HtmlCalls[1].Subject);
        Assert.Equal("No complete internal brief is available. Generate one first.", failedInternal.Message);
        Assert.Equal(2, sender.HtmlCalls.Count);
    }

    private static DashboardBriefSnapshot Snapshot(
        string? unified,
        string globalRisk,
        string internalRisk,
        string? globalBrief = null,
        string? internalBrief = null) => new(
        null, null, globalBrief, null, internalBrief, null, unified, null, globalRisk, internalRisk);

    private static InternalRiskSnapshotEntry Risk(string riskLevel)
    {
        using var json = JsonDocument.Parse("[]");
        return new InternalRiskSnapshotEntry(
            1, DateTime.UtcNow, 10, riskLevel, 1, 0, 0,
            json.RootElement.Clone(), json.RootElement.Clone(), "auto");
    }

    private sealed class StubDashboardStore(DashboardBriefSnapshot? snapshot) : IOperationalDashboardStore
    {
        public Task<DashboardMetrics> GetMetricsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken) =>
            Task.FromResult(new DashboardMetrics(0, 0, 0, 0));
        public Task<IReadOnlyList<DashboardRegionalHazard>> GetHazardsAsync(DateTime nowUtc, int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DashboardRegionalHazard>>([]);
        public Task<IReadOnlyList<DailyThreatScoreEntry>> GetThreatTrendsAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<DailyThreatScoreEntry>>([]);
        public Task<DashboardBriefSnapshot?> GetBriefsAsync(CancellationToken cancellationToken) => Task.FromResult(snapshot);
        public Task<bool> SaveUnifiedBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SaveGlobalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
        public Task<bool> SaveInternalBriefAsync(string content, DateTime savedAtUtc, CancellationToken cancellationToken) =>
            Task.FromResult(true);
    }

    private sealed class StubInternalRiskStore(InternalRiskSnapshotEntry? snapshot) : IInternalRiskStore
    {
        public Task<InternalRiskSnapshotEntry?> GetLatestAsync(CancellationToken cancellationToken) => Task.FromResult(snapshot);
        public Task<IReadOnlyList<InternalRiskHistoryPoint>> GetHistoryAsync(DateTime sinceUtc, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<InternalRiskHistoryPoint>>([]);
    }

    private sealed class StubEmailSender : IEmailSender
    {
        public string? Recipient { get; private set; }
        public string? Subject { get; private set; }
        public string? Body { get; private set; }
        public List<(string Subject, string Body)> HtmlCalls { get; } = [];
        public Task<EmailSendResult> SendPlainTextAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken) =>
            Task.FromResult(new EmailSendResult(true, "sent"));
        public Task<EmailSendResult> SendHtmlAsync(string recipientOverride, string subject, string body, CancellationToken cancellationToken)
        {
            Recipient = recipientOverride;
            Subject = subject;
            Body = body;
            HtmlCalls.Add((subject, body));
            return Task.FromResult(new EmailSendResult(true, "sent"));
        }
        public Task<EmailSendResult> SendHtmlWithAttachmentsAsync(
            string recipientOverride, string subject, string body, IReadOnlyList<EmailAttachment> attachments,
            CancellationToken cancellationToken) => SendHtmlAsync(recipientOverride, subject, body, cancellationToken);
    }
}
