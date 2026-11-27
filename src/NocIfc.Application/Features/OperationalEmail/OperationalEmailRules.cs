using System.Net.Mail;
using System.Text.RegularExpressions;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Application.Features.OperationalEmail;

public static class OperationalEmailRules
{
    private static readonly Regex EmailPattern = new(
        "^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\\.)+[A-Z]{2,63}$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex TokenPattern = new(@"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string[] NormalizeRecipients(string? value)
    {
        if (value is null || string.IsNullOrWhiteSpace(value)) return [];
        var recipients = value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (recipients.Length > 100)
        {
            throw new ArgumentException("No more than 100 recipients may be used per field.");
        }
        if (recipients.Any(recipient => recipient.Length > 254 || !EmailPattern.IsMatch(recipient)))
        {
            throw new ArgumentException("Recipients must be valid email addresses separated by commas or semicolons.");
        }
        return recipients.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    public static string ParseAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "";
        return MailAddress.TryCreate(value, out var address) ? address.Address : "";
    }

    public static string GlobalSenderRecipient(AiSmtpSettings? settings)
    {
        var sender = settings?.ActiveSmtpProvider == "gmail"
            ? string.IsNullOrEmpty(settings.GmailSmtpSender) ? settings.GmailSmtpUsername : settings.GmailSmtpSender
            : settings?.SmtpSender;
        return ParseAddress(sender);
    }

    public static string JoinUnique(IEnumerable<string> values) =>
        string.Join(", ", values.Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase));

    public static (string Name, string Content) ValidateSignature(string? name, string? content)
    {
        if (name is null || !name.Trim().Any() || name.Trim().Length > 100)
        {
            throw new ArgumentException("Signature name must contain 1–100 characters.");
        }
        var normalizedName = name.Trim();
        if (normalizedName.Any(character => character < ' ' && character != '\t' || character == 127))
        {
            throw new ArgumentException("Signature name contains unsupported control characters.");
        }
        if (content is null || !content.Trim().Any() || content.Length > 4000)
        {
            throw new ArgumentException("Signature content must contain 1–4,000 characters.");
        }
        var normalizedContent = content.Trim();
        if (normalizedContent.Contains('\0'))
        {
            throw new ArgumentException("Signature content contains an unsupported character.");
        }
        return (normalizedName, normalizedContent);
    }

    public static string ValidateTemplateText(
        OperationalEmailTemplateDefinition template,
        string? value,
        string label)
    {
        if (value is null || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"{label} is required.");
        }
        var maximum = label == "Default subject" ? 500 : 200_000;
        if (value.Length > maximum)
        {
            throw new ArgumentException($"{label} is too long.");
        }
        if (label == "Default subject" && (value.Contains('\r') || value.Contains('\n')))
        {
            throw new ArgumentException("Default subject cannot contain line breaks.");
        }
        var supported = template.Fields.Select(field => field.Key).ToHashSet(StringComparer.Ordinal);
        var unknown = TokenPattern.Matches(value).Select(match => match.Groups[1].Value)
            .Where(token => !supported.Contains(token)).Distinct(StringComparer.Ordinal)
            .OrderBy(token => token, StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported template placeholder(s): {string.Join(", ", unknown)}.");
        }
        return value.Trim();
    }

    public static bool ContainsTemplateTokens(string value) => TokenPattern.IsMatch(value);
}
