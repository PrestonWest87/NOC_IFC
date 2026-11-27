using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Dashboard;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Reporting;

namespace NocIfc.Application.Features.Email;

public sealed class BriefBroadcastCommands(
    IOperationalDashboardStore dashboard,
    IInternalRiskStore internalRisk,
    IEmailSender emailSender)
{
    private static readonly TimeZoneInfo CentralTimeZone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
    private static readonly Regex Disclaimer = new(
        "^---\\s*\\n\\*\\*OSINT CORRELATION DISCLAIMER:\\*\\*\\s*(.*?)\\n\\s*\\n\\*\\*AI-GENERATED CONTENT:\\*\\*\\s*(.*?)\\n---",
        RegexOptions.Singleline | RegexOptions.Multiline | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<EmailSendResult> BroadcastUnifiedAsync(string email, CancellationToken cancellationToken)
    {
        if (email.Length > 2000)
        {
            throw new ArgumentException("Recipient email must be 2,000 characters or fewer.");
        }
        if (email.Length == 0)
        {
            return new EmailSendResult(false, "No recipient email specified.");
        }

        var briefs = await dashboard.GetBriefsAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(briefs?.UnifiedBrief))
        {
            return new EmailSendResult(false, "No unified brief available. Generate one first.");
        }

        var latestInternal = await internalRisk.GetLatestAsync(cancellationToken);
        var globalRisk = NormalizeRisk(briefs.LastGlobalRisk);
        var internalLevel = NormalizeRisk(latestInternal?.RiskLevel ?? briefs.LastInternalRisk);
        var reportTime = FormatReportTime();
        var html = FormatUnifiedBriefEmail(reportTime, briefs.UnifiedBrief, globalRisk, internalLevel);
        return await emailSender.SendHtmlAsync(email, "Executive Unified Risk Brief", html, cancellationToken);
    }

    public async Task<EmailSendResult> BroadcastGlobalAsync(string email, CancellationToken cancellationToken)
    {
        if (email.Length > 2000) throw new ArgumentException("Recipient email must be 2,000 characters or fewer.");
        if (email.Length == 0) return new EmailSendResult(false, "No recipient email specified.");

        var briefs = await dashboard.GetBriefsAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(briefs?.GlobalBrief))
        {
            return new EmailSendResult(false, "No global brief available. Generate one first.");
        }
        var latestInternal = await internalRisk.GetLatestAsync(cancellationToken);
        var globalRisk = NormalizeRisk(briefs.LastGlobalRisk);
        var internalLevel = NormalizeRisk(latestInternal?.RiskLevel ?? briefs.LastInternalRisk);
        var globalDisplay = Display(globalRisk);
        var (markdown, disclaimer) = ExtractDisclaimer(briefs.GlobalBrief);
        var html = FormatOtherBriefEmail(
            "Global Threat Brief — US CI & International", "#dc2626", FormatReportTime(),
            $"The current Global Threat Posture of {globalDisplay} is assessed and determined by the AECC/CI Cyber Security Director.",
            RiskBadge("Global Threat Posture", globalRisk, 50) + RiskBadge("Internal Cyber Risk", internalLevel, 50),
            disclaimer + ReportingBroadcastCommands.RenderMarkdown(markdown) + GlobalDisclaimer());
        return await emailSender.SendHtmlAsync(
            email, "Global Threat Brief - US Critical Infrastructure", html, cancellationToken);
    }

    public async Task<EmailSendResult> BroadcastInternalAsync(string email, CancellationToken cancellationToken)
    {
        if (email.Length > 2000) throw new ArgumentException("Recipient email must be 2,000 characters or fewer.");
        if (email.Length == 0) return new EmailSendResult(false, "No recipient email specified.");

        var briefs = await dashboard.GetBriefsAsync(cancellationToken);
        if (string.IsNullOrWhiteSpace(briefs?.InternalBrief)
            || DashboardQueries.IsInternalRiskBriefFailureNotice(briefs.InternalBrief))
        {
            return new EmailSendResult(false, "No complete internal brief is available. Generate one first.");
        }
        var latestInternal = await internalRisk.GetLatestAsync(cancellationToken);
        var globalRisk = NormalizeRisk(briefs.LastGlobalRisk);
        var internalLevel = NormalizeRisk(latestInternal?.RiskLevel ?? briefs.LastInternalRisk);
        var internalDisplay = Display(internalLevel);
        var (markdown, disclaimer) = ExtractDisclaimer(briefs.InternalBrief);
        var html = FormatOtherBriefEmail(
            "Internal Asset Risk Brief", "#7c3aed", FormatReportTime(),
            $"The current Internal Threat Posture of {internalDisplay} is assessed and determined by the AECC/CI Cyber Security Director.",
            RiskBadge("Internal Cyber Risk", internalLevel, 50) + RiskBadge("Global Threat Posture", globalRisk, 50),
            disclaimer + ReportingBroadcastCommands.RenderMarkdown(markdown));
        return await emailSender.SendHtmlAsync(email, "Internal Asset Risk Brief", html, cancellationToken);
    }

    private static string FormatUnifiedBriefEmail(
        string reportTime,
        string markdown,
        string globalRisk,
        string internalRisk)
    {
        var overallRisk = Tier(globalRisk) >= Tier(internalRisk) ? globalRisk : internalRisk;
        var (cleanMarkdown, disclaimerHtml) = ExtractDisclaimer(markdown);
        var cyberLine = $"The current Internal Threat Posture of {Display(internalRisk)} is assessed and determined by the AECC/CI Cyber Security Director.";
        return $"""
            <div style="margin:0;padding:20px;background:#f3f4f6;">
              <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;max-width:850px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
                <div style="background:#1f2937;padding:25px 30px;">
                  <h1 style="color:#fff;margin:0 0 5px;font-size:22px;font-weight:600;">Executive Unified Risk Brief</h1>
                  <p style="color:#9ca3af;margin:0;font-size:13px;">Generated: {WebUtility.HtmlEncode(reportTime)}</p>
                </div>
                <div style="padding:30px;font-size:14px;line-height:1.6;color:#374151;">
                  <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:25px;table-layout:fixed;"><tr>
                    {RiskBadge("Unified Posture", overallRisk)}
                    {RiskBadge("Global Risk", globalRisk)}
                    {RiskBadge("Internal Cyber Risk", internalRisk)}
                  </tr></table>
                  <p style="font-size:14px;line-height:1.6;margin:0 0 15px;"><strong>{WebUtility.HtmlEncode(cyberLine)}</strong></p>
                  {disclaimerHtml}{ReportingBroadcastCommands.RenderMarkdown(cleanMarkdown)}
                </div>
                <div style="background:#f9fafb;padding:14px 30px;text-align:center;border-top:1px solid #e5e7eb;">
                  <p style="margin:0;font-size:11px;color:#9ca3af;">NOC Intelligence Fusion Center &middot; Internal Use Only</p>
                </div>
              </div>
            </div>
            """;
    }

    private static string FormatOtherBriefEmail(
        string title,
        string headerColor,
        string reportTime,
        string postureLine,
        string badges,
        string body) => $"""
        <div style="margin:0;padding:20px;background:#f3f4f6;">
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;max-width:850px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
            <div style="background:{headerColor};padding:25px 30px;">
              <h1 style="color:#fff;margin:0 0 5px;font-size:22px;font-weight:600;">{WebUtility.HtmlEncode(title)}</h1>
              <p style="color:#fecaca;margin:0;font-size:13px;">Generated: {WebUtility.HtmlEncode(reportTime)}</p>
            </div>
            <div style="padding:30px 30px 10px;font-size:14px;line-height:1.6;color:#374151;">
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:25px;table-layout:fixed;"><tr>{badges}</tr></table>
              <p style="font-size:14px;line-height:1.6;margin:0 0 15px;"><strong>{WebUtility.HtmlEncode(postureLine)}</strong></p>
              {body}
            </div>
            <div style="background:#f9fafb;padding:14px 30px;text-align:center;border-top:1px solid #e5e7eb;">
              <p style="margin:0;font-size:11px;color:#9ca3af;">NOC Intelligence Fusion Center &middot; Internal Use Only</p>
            </div>
          </div>
        </div>
        """;

    private static (string Markdown, string Html) ExtractDisclaimer(string markdown)
    {
        var match = Disclaimer.Match(markdown);
        if (!match.Success) return (markdown, "");
        var html = $"""
            <div style="background:#f8f9fa;border-left:4px solid #6b7280;border-radius:4px;padding:14px 18px;margin-bottom:24px;">
              <p style="font-size:11px;font-weight:700;color:#6b7280;margin:0 0 8px;text-transform:uppercase;">Disclaimers</p>
              <p style="font-size:12.5px;color:#4b5563;line-height:1.5;margin:0 0 8px;"><strong>OSINT Correlation:</strong> {WebUtility.HtmlEncode(match.Groups[1].Value.Trim())}</p>
              <p style="font-size:12.5px;color:#4b5563;line-height:1.5;margin:0;"><strong>AI-Generated Content:</strong> {WebUtility.HtmlEncode(match.Groups[2].Value.Trim())}</p>
            </div>
            """;
        return (markdown.Replace(match.Value, "", StringComparison.Ordinal).Trim(), html);
    }

    private static string GlobalDisclaimer() => """
        <div style="background:#f8f9fa;border-left:4px solid #6b7280;border-radius:4px;padding:14px 18px;margin-top:24px;">
          <p style="font-size:11px;font-weight:700;color:#6b7280;margin:0 0 8px;text-transform:uppercase;">Disclaimers</p>
          <p style="font-size:12.5px;color:#4b5563;line-height:1.5;margin:0 0 8px;"><strong>OSINT Correlation:</strong> This brief synthesizes external Open-Source Intelligence (OSINT) for situational awareness; it does not represent confirmed compromises of our systems or facilities.</p>
          <p style="font-size:12.5px;color:#4b5563;line-height:1.5;margin:0;"><strong>AI-Generated Content:</strong> This brief was generated by the internal NOC AIOps system and has not been thoroughly reviewed by a human security analyst.</p>
        </div>
        """;

    private static string RiskBadge(string title, string risk, int width = 33)
    {
        var (display, color) = RiskStyle(risk);
        return $"""
            <td width="{width}%" align="center" valign="top" style="padding:5px;">
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8f9fa;border:1px solid #e5e7eb;border-radius:8px;">
                <tr><td align="center" style="padding:15px 10px;">
                  <div style="font-size:11px;font-weight:700;color:#6b7280;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;">{WebUtility.HtmlEncode(title)}</div>
                  <div style="background:{color};color:#fff;font-size:14px;font-weight:bold;padding:6px 16px;border-radius:20px;">{WebUtility.HtmlEncode(display)}</div>
                </td></tr>
              </table>
            </td>
            """;
    }

    private static string NormalizeRisk(string? risk) =>
        string.IsNullOrWhiteSpace(risk) ? "UNKNOWN" : risk.Trim().ToUpperInvariant();

    private static string FormatReportTime()
    {
        var now = TimeZoneInfo.ConvertTime(DateTimeOffset.UtcNow, CentralTimeZone);
        var zone = now.Offset == TimeSpan.FromHours(-5) ? "CDT" : "CST";
        return $"{now.ToString("dddd, MMMM dd, yyyy 'at' hh:mm tt", CultureInfo.InvariantCulture)} {zone}";
    }

    private static int Tier(string risk) => risk switch
    {
        "GREEN" => 1,
        "BLUE" => 2,
        "YELLOW" => 3,
        "ORANGE" => 4,
        "RED" => 5,
        _ => 0,
    };

    private static (string Display, string Color) RiskStyle(string risk) => risk switch
    {
        "GREEN" => ("LOW", "#01a46d"),
        "BLUE" => ("GUARDED", "#377fc7"),
        "YELLOW" => ("ELEVATED", "#f5d800"),
        "ORANGE" => ("HIGH", "#ff9b2b"),
        "RED" => ("SEVERE", "#ec3e40"),
        _ => (risk, "#6c757d"),
    };

    private static string Display(string risk) => RiskStyle(risk).Display;
}
