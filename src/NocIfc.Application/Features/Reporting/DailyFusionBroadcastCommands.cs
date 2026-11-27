using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Application.Features.Reporting;

public sealed class DailyFusionBroadcastCommands(IEmailSender emailSender)
{
    public async Task<EmailSendResult> BroadcastAsync(
        string reportDate,
        string content,
        string recipients,
        CancellationToken cancellationToken)
    {
        if (reportDate.Length > 50 || content.Length > 200_000 || recipients.Length > 2_000)
        {
            throw new ArgumentException("Daily Fusion email fields exceed their maximum length.");
        }
        var normalizedRecipients = NormalizeRecipients(recipients);
        if (normalizedRecipients.Length == 0)
        {
            return new EmailSendResult(false, "No recipients specified.");
        }
        var html = FormatEmail(reportDate, content);
        return await emailSender.SendHtmlAsync(
            normalizedRecipients,
            $"Daily Fusion Report - {reportDate}",
            html,
            cancellationToken);
    }

    private static string NormalizeRecipients(string recipients)
    {
        if (recipients.Contains('\r') || recipients.Contains('\n'))
        {
            throw new ArgumentException("Recipients cannot contain newlines.");
        }
        var addresses = recipients.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Trim())
            .Where(part => part.Length > 0)
            .ToArray();
        if (addresses.Length > 20)
        {
            throw new ArgumentException("A maximum of 20 recipients is allowed.");
        }
        if (addresses.Any(address => !EmailAddressRules.IsValid(address)))
        {
            throw new ArgumentException("Recipients must be valid email addresses separated by commas or semicolons.");
        }
        return string.Join(", ", addresses);
    }

    private static string FormatEmail(string reportDate, string content)
    {
        var renderedContent = RenderMarkdown(content);
        return $"""
            <div style="font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;max-width:900px;margin:0 auto;color:#333;line-height:1.5;">
              <div style="background-color:#fcfcfc;padding:20px;border-radius:6px;border-left:4px solid #d9534f;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
                <h2 style="color:#2c3e50;margin-top:0;">NOC Daily Fusion Report</h2>
                <p style="color:#7f8c8d;font-size:0.9em;margin-bottom:20px;"><strong>Date:</strong> {WebUtility.HtmlEncode(reportDate)}</p>
                <div style="font-size:14px;background-color:#fff;padding:15px;border-radius:4px;border:1px solid #eee;">
                  {renderedContent}
                </div>
              </div>
            </div>
            """;
    }

    private static string RenderMarkdown(string markdown)
    {
        var output = new StringBuilder();
        var inList = false;
        foreach (var line in markdown.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
            {
                if (inList)
                {
                    output.Append("</ul>");
                    inList = false;
                }
                continue;
            }
            if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith("* ", StringComparison.Ordinal))
            {
                if (!inList)
                {
                    output.Append("<ul style=\"margin:0 0 12px;padding-left:24px;\">");
                    inList = true;
                }
                output.Append("<li>").Append(RenderInline(trimmed[2..])).Append("</li>");
                continue;
            }
            if (inList)
            {
                output.Append("</ul>");
                inList = false;
            }
            var headingLevel = 0;
            while (headingLevel < Math.Min(6, trimmed.Length) && trimmed[headingLevel] == '#') headingLevel++;
            if (headingLevel > 0 && headingLevel < trimmed.Length && trimmed[headingLevel] == ' ')
            {
                var heading = RenderInline(trimmed[(headingLevel + 1)..]);
                output.Append($"<h{headingLevel} style=\"color:#2c3e50;margin:18px 0 8px;\">{heading}</h{headingLevel}>");
            }
            else
            {
                output.Append("<p style=\"margin:0 0 12px;line-height:1.6;\">")
                    .Append(RenderInline(trimmed)).Append("</p>");
            }
        }
        if (inList) output.Append("</ul>");
        return output.ToString();
    }

    private static string RenderInline(string value)
    {
        var encoded = WebUtility.HtmlEncode(value);
        encoded = Regex.Replace(encoded, @"\*\*(.+?)\*\*", "<strong>$1</strong>");
        return Regex.Replace(encoded, @"\*(.+?)\*", "<em>$1</em>");
    }
}
