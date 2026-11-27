using System.Text.Json;
using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Settings;
using NocIfc.Application.Features.Settings;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.AIOps;

public sealed record TieredAlertEscalationResult(int TicketsSent, int PagesSent);

public sealed class TieredAlertEscalationCommands(
    IAiopsRcaAnalysisStore analysisStore,
    IAiopsDashboardStore dashboardStore,
    AiopsRcaAnalysisEngine engine,
    AiopsDashboardQueries dashboard,
    IAutoEscalationStore escalation,
    IFacilityDirectoryStore facilities,
    IOperationalIntegrationSettingsStore integration,
    IEmailSender emailSender)
{
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
    private static readonly AuthenticatedUser SystemUser = new(0, "scheduler", "administrator", [], [], []);
    private static readonly IReadOnlyDictionary<string, EscalationRule> DayRules = new Dictionary<string, EscalationRule>(StringComparer.Ordinal)
    {
        ["p1-high"] = new(0, "1 Hour", 70, false, 1),
        ["p1-low"] = new(0, "4 Hours", 60, false, 1),
        ["p2-high"] = new(10, "2.5 Hours", 50, false, 5),
        ["p2-low"] = new(10, "4 Hours", 40, false, 5),
        ["p3"] = new(10, "8 Hours", 30, false, 5),
        ["p4"] = new(10, "24 Hours", 20, false, 5),
        ["p5"] = new(10, "72 Hours", 10, false, 5),
    };
    private static readonly IReadOnlyDictionary<string, EscalationRule> AfterHoursRules = new Dictionary<string, EscalationRule>(StringComparer.Ordinal)
    {
        ["p1-high"] = new(0, "1 Hour", 70, true, 1),
        ["p1-low"] = new(45, "4 Hours", 60, true, 1),
        ["p2-high"] = new(30, "2.5 Hours", 50, false, 5),
        ["p2-low"] = new(45, "4 Hours", 40, false, 5),
        ["p3"] = new(45, "8 Hours", 30, false, 5),
        ["p4"] = new(60, "24 Hours", 20, false, 5),
        ["p5"] = new(120, "72 Hours", 10, false, 5),
    };

    public static string GetTier(AiopsAlertEntry alert)
    {
        if (!string.IsNullOrWhiteSpace(alert.RawPayloadJson))
        {
            try
            {
                using var document = JsonDocument.Parse(alert.RawPayloadJson);
                var root = document.RootElement;
                var value = ReadString(root, "Normalized_Alert_Level");
                if (string.IsNullOrWhiteSpace(value)
                    && root.TryGetProperty("Custom_Properties_Universal", out var custom))
                {
                    value = ReadString(custom, "Alert_Level");
                }
                var normalized = (value ?? "").Trim().ToLowerInvariant();
                foreach (var tier in new[] { "p1-high", "p1-low", "p2-high", "p2-low" })
                {
                    if (normalized.Contains(tier, StringComparison.Ordinal)) return tier;
                }
                var number = new string(normalized.Where(char.IsAsciiDigit).ToArray());
                if (number.Length > 0 && int.TryParse(number, out var level))
                {
                    if (level == 1) return normalized.Contains("low", StringComparison.Ordinal) ? "p1-low" : "p1-high";
                    if (level == 2) return normalized.Contains("low", StringComparison.Ordinal) ? "p2-low" : "p2-high";
                    if (level is >= 3 and <= 5) return $"p{level}";
                }
            }
            catch (JsonException)
            {
            }
        }
        return "unknown";
    }

    public static bool IsBusinessHours(DateTime? timestampUtc)
    {
        if (timestampUtc is null) return false;
        var utc = DateTime.SpecifyKind(timestampUtc.Value, DateTimeKind.Utc);
        var local = TimeZoneInfo.ConvertTimeFromUtc(utc, CentralTimeZone);
        return local.DayOfWeek is >= DayOfWeek.Monday and <= DayOfWeek.Friday
            && local.Hour is >= 6 and < 20;
    }

    public async Task<TieredAlertEscalationResult> ExecuteAsync(CancellationToken cancellationToken)
    {
        var settings = await integration.GetAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(settings.RemedyforceTicketEmail)) return new TieredAlertEscalationResult(0, 0);
        var now = DateTime.UtcNow;
        var activeAlerts = await dashboardStore.GetActiveAlertsAsync(null, now.AddHours(-12), cancellationToken);
        if (activeAlerts.Count == 0) return new TieredAlertEscalationResult(0, 0);
        var locations = await dashboard.GetSitesAsync(SystemUser, cancellationToken);
        var events = await dashboardStore.GetTimelineEventsAsync(null, 50, cancellationToken);
        var context = await analysisStore.GetAnalysisContextAsync(
            now, now.AddDays(-60), includeHistory: false, cancellationToken: cancellationToken);
        var report = engine.Analyze(activeAlerts, events, locations, context, false, now);
        var locationByName = locations.Where(location => !string.IsNullOrEmpty(location.Name))
            .GroupBy(location => location.Name!, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var ticketsSent = 0;
        var pagesSent = 0;

        foreach (var (site, cluster) in report.Clustered)
        {
            var alerts = cluster.Alerts.Where(alert => alert.Status != "Resolved"
                && alert.ReceivedAt >= now.AddHours(-12)).ToArray();
            if (alerts.Length == 0) continue;
            locationByName.TryGetValue(site, out var location);
            var ticketCandidates = new List<Candidate>();
            var pageCandidates = new List<Candidate>();
            foreach (var alert in alerts)
            {
                var tier = GetTier(alert);
                var rule = RuleFor(tier, IsBusinessHours(alert.ReceivedAt));
                if (!alert.IsTicketed && !alert.IsDispatched
                    && !await escalation.IsNodeOnCooldownAsync(alert.Id, alert.NodeName ?? "", site,
                        now.AddHours(-rule.CooldownHours), cancellationToken))
                {
                    ticketCandidates.Add(new Candidate(alert, tier, rule));
                }
                if (!rule.RequiresOnPage || await escalation.IsNodePagedAsync(
                        site, alert.NodeName, alert.Id, cancellationToken))
                {
                    continue;
                }
                if (!alert.IsTicketed && await escalation.IsNodeOnCooldownAsync(
                        alert.Id, alert.NodeName ?? "", site, now.AddHours(-rule.CooldownHours), cancellationToken))
                {
                    continue;
                }
                pageCandidates.Add(new Candidate(alert, tier, rule));
            }

            var ticketTarget = SelectTarget(ticketCandidates, now);
            var pageTarget = SelectTarget(pageCandidates, now);
            var ticketDue = ticketTarget is not null && IsDue(ticketTarget, now);
            var pageDue = pageTarget is not null && IsDue(pageTarget, now)
                && !IsBusinessHours(pageTarget.Alert.ReceivedAt);
            if (ticketDue && location?.LastEscalationTicket is { } lastPage
                && now - DateTime.SpecifyKind(lastPage, DateTimeKind.Utc) < TimeSpan.FromHours(1)
                && !IsBusinessHours(ticketTarget!.Alert.ReceivedAt)
                && ticketTarget.Tier is not ("p1-high" or "p1-low"))
            {
                ticketDue = false;
            }
            if (!ticketDue && !pageDue) continue;

            report.RootCause.TryGetValue(site, out var rootCause);
            var ticketBody = ticketDue
                ? BuildBody(site, cluster, ticketTarget!, rootCause, location)
                : "";
            var ticketSent = false;
            if (ticketDue)
            {
                var ticket = ticketTarget!;
                var ticketDay = IsBusinessHours(ticket.Alert.ReceivedAt);
                var prefix = $"{(ticketDay ? "DAY-SHIFT" : "AFTER-HOURS")} {(ticket.IsCascade ? "SITE ESCALATION / CASCADE" : "TICKET")}";
                var subject = ticket.Tier == "unknown"
                    ? $"UNDOCUMENTED ALERT: {CleanHeader(ticket.Alert.NodeName)}"
                    : $"{(ticket.IsCascade ? "CASCADE " : "")}TICKET: {ticket.Tier.ToUpperInvariant()} Incident at {CleanHeader(site)}";
                if (ticket.Tier == "unknown")
                {
                    ticketBody = "*** REQUIRES MANAGEMENT DIRECTION ***\n"
                        + $"Unmapped Priority: {ticket.Alert.EventType}\n\n{ticketBody}";
                }
                else
                {
                    ticketBody = $"*** {prefix} ***\n{ticketBody}";
                }
                ticketSent = (await emailSender.SendPlainTextAsync(
                    settings.RemedyforceTicketEmail, subject, ticketBody, cancellationToken)).Success;
                if (ticketSent)
                {
                    ticketsSent++;
                    await escalation.MarkTicketedAsync(alerts.Select(alert => alert.Id).ToArray(), cancellationToken);
                    if (!ticketDay && !string.IsNullOrWhiteSpace(settings.NocNotifyEmail))
                    {
                        var notificationSubject = ticket.Tier == "unknown"
                            ? $"UNDOCUMENTED ALERT (NOTIFY): {CleanHeader(ticket.Alert.NodeName)}"
                            : $"NOC NOTIFICATION {(ticket.IsCascade ? "(CASCADE) " : "")}: {ticket.Tier.ToUpperInvariant()} Incident at {CleanHeader(site)}";
                        await emailSender.SendPlainTextAsync(settings.NocNotifyEmail, notificationSubject,
                            $"*** NOC NOTIFICATION {(ticket.IsCascade ? "ESCALATION " : "")}***\n{ticketBody}", cancellationToken);
                    }
                }
            }

            if (pageDue)
            {
                var page = pageTarget!;
                var nodeName = page.Alert.NodeName ?? "";
                var fiberDevice = nodeName.Contains("swf", StringComparison.OrdinalIgnoreCase)
                    || location?.LocationType?.Contains("fiber hut", StringComparison.OrdinalIgnoreCase) == true
                    || location?.LocationType?.Contains("fiber cabinet", StringComparison.OrdinalIgnoreCase) == true;
                var recipient = fiberDevice ? settings.NocOnpageEmail : settings.ItnetworkOnpageEmail;
                if (!string.IsNullOrWhiteSpace(recipient))
                {
                    var body = BuildBody(site, cluster, page, rootCause, location);
                    var contacts = location is null
                        ? null
                        : await facilities.GetSiteContactsAsync(location.Id, cancellationToken);
                    var contactBlock = FormatContacts(contacts);
                    if (contactBlock.Length > 0)
                    {
                        var separator = body.IndexOf("\n\n", StringComparison.Ordinal);
                        if (separator >= 0) body = body[..separator] + "\n\n" + contactBlock + body[separator..];
                    }
                    var onpageName = fiberDevice ? "NOC" : "ITNETWORK";
                    var subject = $"URGENT {onpageName} ONPAGE {(page.IsCascade ? "CASCADE " : "")}: {page.Tier.ToUpperInvariant()} Incident at {CleanHeader(site)}";
                    var success = (await emailSender.SendPlainTextAsync(recipient, subject,
                        $"*** URGENT {onpageName} ONPAGE {(page.IsCascade ? "ESCALATION " : "")}***\n{body}",
                        cancellationToken)).Success;
                    if (success)
                    {
                        pagesSent++;
                        await escalation.MarkPageSentAsync(site, page.Alert.NodeName, page.Alert.Id, now, cancellationToken);
                    }
                }
            }
        }
        return new TieredAlertEscalationResult(ticketsSent, pagesSent);
    }

    private static string BuildBody(
        string site,
        AiopsRcaCluster cluster,
        Candidate target,
        AiopsRootCause? rootCause,
        MonitoredLocationEntry? location)
    {
        var rule = RuleFor(target.Tier, IsBusinessHours(target.Alert.ReceivedAt));
        var patientZero = cluster.PatientZero?.ReceivedAt?.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        var alerts = cluster.Alerts.Select(alert => new AiopsTicketTextAlert(
            alert.ReceivedAt?.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            alert.NodeName ?? "Unknown",
            alert.IpAddress ?? "Unknown",
            alert.Status ?? "Unknown",
            alert.EventCategory ?? "Unknown")).ToArray();
        var input = new AiopsTicketTextInput(
            site, target.Tier.ToUpperInvariant(), rootCause?.Cause, patientZero,
            location?.District ?? cluster.SiteMetadata.District,
            cluster.DomainsAffected, alerts);
        var body = $"Target SLA: {rule.Sla}\n";
        if (target.Tier == "p2-high" && !IsBusinessHours(target.Alert.ReceivedAt))
        {
            body += "Requirement: Positive Handoff (No ONPAGE)\n";
        }
        body += "\n" + AiopsRcaTicketTextGenerator.Generate(input);
        return body;
    }

    private static Candidate? SelectTarget(IReadOnlyList<Candidate> candidates, DateTime now)
    {
        if (candidates.Count == 0) return null;
        var ordered = candidates.OrderBy(candidate => candidate.Alert.ReceivedAt ?? now).ToArray();
        var target = ordered[0];
        var initialWeight = target.Rule.Weight;
        var targetWeight = initialWeight;
        var cascade = false;
        foreach (var candidate in ordered.Skip(1))
        {
            if (candidate.Rule.Weight <= targetWeight) continue;
            target = candidate;
            targetWeight = candidate.Rule.Weight;
            cascade = targetWeight > initialWeight;
        }
        return target with { IsCascade = cascade };
    }

    private static bool IsDue(Candidate candidate, DateTime now)
    {
        var wait = candidate.Rule.WaitMinutes;
        if (candidate.IsCascade) wait = 0;
        return now - (candidate.Alert.ReceivedAt ?? now) >= TimeSpan.FromMinutes(wait);
    }

    private static EscalationRule RuleFor(string tier, bool isDay)
    {
        var rules = isDay ? DayRules : AfterHoursRules;
        if (rules.TryGetValue(tier, out var rule)) return rule;
        return new EscalationRule(isDay ? 10 : 30, "N/A", -1, false, 5);
    }

    private static string FormatContacts(IReadOnlyList<MonitoredLocationContactEntry>? contacts)
    {
        if (contacts is null) return "";
        var lines = contacts.Select(contact =>
        {
            var fields = new List<string>();
            var name = CleanLine(contact.Name);
            var phone = CleanLine(contact.Phone);
            var email = CleanLine(contact.Email);
            if (name.Length > 0) fields.Add(name);
            if (phone.Length > 0) fields.Add($"Phone: {phone}");
            if (email.Length > 0) fields.Add($"Email: {email}");
            return fields.Count == 0 ? "" : $"- {string.Join(" | ", fields)}";
        }).Where(line => line.Length > 0).ToArray();
        return lines.Length == 0 ? "" : "SITE CONTACTS (REFERENCE ONLY)\n" + string.Join('\n', lines);
    }

    private static string CleanLine(string? value) =>
        string.Join(' ', (value ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string CleanHeader(string? value) => CleanLine(value).Replace('\r', ' ').Replace('\n', ' ');

    private static string? ReadString(JsonElement value, string property) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(property, out var child)
            && child.ValueKind == JsonValueKind.String ? child.GetString() : null;

    private sealed record EscalationRule(int WaitMinutes, string Sla, int Weight, bool RequiresOnPage, int CooldownHours);
    private sealed record Candidate(AiopsAlertEntry Alert, string Tier, EscalationRule Rule, bool IsCascade = false);
}
