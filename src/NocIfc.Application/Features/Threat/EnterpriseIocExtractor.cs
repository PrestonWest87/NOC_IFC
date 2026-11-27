using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public static class EnterpriseIocExtractor
{
    private const int ContextWindow = 45;
    private static readonly HashSet<string> IgnoreDomains = new(
        ["example.com", "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "mitre.org", "nist.gov", "virustotal.com", "shodan.io", "schema.org", "w3.org", "wikipedia.org", "iana.org"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> IgnoreIps = new(
        ["0.0.0.0", "255.255.255.255", "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"],
        StringComparer.Ordinal);
    private static readonly RegexOptions Options =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled;
    private static readonly IocRule[] Rules =
    [
        Rule("Network", "IPv4", @"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        Rule("Network", "IPv6", @"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b"),
        Rule("Network", "URL", @"(?:https?|ftp|tcp|udp|ldaps?)://[\w/\-?=%.]+\.[\w/\-&?=%.]+"),
        Rule("Network", "Domain", @"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|biz|co|us|uk|ru|cn|gov|edu|mil|int|dev|ai|app|xyz)\b"),
        Rule("Network", "Email", @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        Rule("Network", "ASN", @"\bAS\d{3,6}\b"),
        Rule("Host Artifacts", "SHA256", @"\b[A-Fa-f0-9]{64}\b"),
        Rule("Host Artifacts", "SHA1", @"\b[A-Fa-f0-9]{40}\b"),
        Rule("Host Artifacts", "MD5", @"\b[A-Fa-f0-9]{32}\b"),
        Rule("Host Artifacts", "Registry Key", @"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+\b"),
        Rule("Host Artifacts", "Windows Path", @"\b[A-Za-z]:\\[a-zA-Z0-9_\\\-.\s]+\b"),
        Rule("Host Artifacts", "Linux Path", @"\b/(?:bin|etc|var|usr|tmp|opt|home|root)(?:/[a-zA-Z0-9_.-]+)+\b"),
        Rule("Actor Infrastructure", "BTC Wallet", @"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
        Rule("Actor Infrastructure", "XMR Wallet", @"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
        Rule("Actor Infrastructure", "Discord C2", @"(?:discord\.com/api/webhooks/|discordapp\.com/api/webhooks/)[\w-]+/[\w-]+"),
        Rule("Actor Infrastructure", "Telegram C2", @"(?:api\.telegram\.org/bot)[\w:-]+"),
        Rule("Cloud & DevOps", "AWS API Key", @"\bAKIA[0-9A-Z]{16}\b"),
        Rule("Cloud & DevOps", "AWS S3 Bucket", @"\b[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com\b"),
        Rule("Cloud & DevOps", "Azure Blob", @"\b[a-z0-9]+\.blob\.core\.windows\.net\b"),
        Rule("Taxonomy", "CVE", @"\bCVE-\d{4}-\d{4,7}\b"),
        Rule("Taxonomy", "MITRE ATT&CK", @"\bT\d{4}(?:\.\d{3})?\b"),
    ];

    public static IReadOnlyList<RssArticleIoc> Extract(string? rawText)
    {
        if (string.IsNullOrEmpty(rawText)) return [];
        var text = Refang(rawText);
        var results = new List<RssArticleIoc>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in Rules)
        {
            foreach (Match match in rule.Pattern.Matches(text))
            {
                var value = match.Value.Trim();
                var normalized = value.ToLowerInvariant();
                if (seen.Contains(normalized)) continue;
                if (rule.Type is "IPv4" or "IPv6")
                {
                    if (!IsPublicIp(value)) continue;
                }
                else if (rule.Type == "Domain")
                {
                    if (IgnoreDomains.Contains(normalized)
                        || seen.Any(existing => existing.StartsWith("http", StringComparison.Ordinal) && existing.Contains(normalized, StringComparison.Ordinal)))
                    {
                        continue;
                    }
                }

                if (rule.Type is "SHA256" or "SHA1" or "MD5" or "CVE" or "MITRE ATT&CK")
                {
                    value = value.ToUpperInvariant();
                }
                else if (rule.Type == "Email")
                {
                    value = normalized;
                }
                results.Add(new RssArticleIoc(rule.Category, rule.Type, value, Context(text, match)));
                seen.Add(normalized);
            }
        }
        return results;
    }

    private static string Refang(string value)
    {
        try
        {
            value = Uri.UnescapeDataString(value);
        }
        catch (UriFormatException)
        {
            // Leave malformed percent escapes intact for regex scanning.
        }
        value = Regex.Replace(value, @"\bhxxps?", "http", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        value = Regex.Replace(value, @"\bfxp", "ftp", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        value = Regex.Replace(value, @"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        value = Regex.Replace(value, @"\[:\]|\(\:\)", ":");
        value = Regex.Replace(value, @"\[/\]|\(\/\)", "/");
        value = Regex.Replace(value, @"\[@\]|\(@\)| AT ", "@", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return Regex.Replace(value, " DOT ", ".", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    private static string Context(string text, Match match)
    {
        var start = Math.Max(0, match.Index - ContextWindow);
        var end = Math.Min(text.Length, match.Index + match.Length + ContextWindow);
        var context = text[start..end].Replace('\n', ' ').Replace("\r", "", StringComparison.Ordinal);
        return $"...{context}...";
    }

    private static bool IsPublicIp(string value)
    {
        if (IgnoreIps.Contains(value) || !IPAddress.TryParse(value, out var address)) return false;
        if (address.IsIPv4MappedToIPv6) return IsPublicIp(address.MapToIPv4().ToString());
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            var first = bytes[0];
            var second = bytes[1];
            var third = bytes[2];
            return !(first is 0 or 10 or 127 || first >= 224
                || first == 100 && second is >= 64 and <= 127
                || first == 169 && second == 254
                || first == 172 && second is >= 16 and <= 31
                || first == 192 && (second == 168 || second == 0 || second == 2)
                || first == 198 && (second == 18 || second == 19 || second == 51 && third == 100)
                || first == 203 && second == 0 && third == 113);
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        var ipv6 = address.GetAddressBytes();
        var allZero = ipv6.All(valueByte => valueByte == 0);
        var loopback = ipv6.Take(15).All(valueByte => valueByte == 0) && ipv6[15] == 1;
        var uniqueLocal = (ipv6[0] & 0xFE) == 0xFC;
        var linkLocal = ipv6[0] == 0xFE && (ipv6[1] & 0xC0) == 0x80;
        var siteLocal = ipv6[0] == 0xFE && (ipv6[1] & 0xC0) == 0xC0;
        var documentation = ipv6[0] == 0x20 && ipv6[1] == 0x01 && ipv6[2] == 0x0D && ipv6[3] == 0xB8;
        return !(allZero || loopback || address.IsIPv6Multicast || uniqueLocal || linkLocal || siteLocal || documentation);
    }

    private static IocRule Rule(string category, string type, string pattern) =>
        new(category, type, new Regex(pattern, Options));

    private sealed record IocRule(string Category, string Type, Regex Pattern);
}
