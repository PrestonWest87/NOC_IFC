using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public static class EnterpriseIocExtractor
{
    private const int ContextWindow = 45;
    // Keep these special-use ranges aligned with the Python 3.11 ipaddress policy.
    private static readonly IPNetwork[] PrivateIpv4 =
    [
        IPNetwork.Parse("0.0.0.0/8"), IPNetwork.Parse("10.0.0.0/8"), IPNetwork.Parse("127.0.0.0/8"),
        IPNetwork.Parse("169.254.0.0/16"), IPNetwork.Parse("172.16.0.0/12"), IPNetwork.Parse("192.0.0.0/24"),
        IPNetwork.Parse("192.0.0.170/31"), IPNetwork.Parse("192.0.2.0/24"), IPNetwork.Parse("192.168.0.0/16"),
        IPNetwork.Parse("198.18.0.0/15"), IPNetwork.Parse("198.51.100.0/24"), IPNetwork.Parse("203.0.113.0/24"),
        IPNetwork.Parse("240.0.0.0/4"), IPNetwork.Parse("255.255.255.255/32"),
    ];
    private static readonly IPNetwork[] PublicIpv4Exceptions =
    [
        IPNetwork.Parse("192.0.0.9/32"), IPNetwork.Parse("192.0.0.10/32"),
    ];
    private static readonly IPNetwork[] PrivateIpv6 =
    [
        IPNetwork.Parse("::/128"), IPNetwork.Parse("::1/128"), IPNetwork.Parse("::ffff:0:0/96"),
        IPNetwork.Parse("64:ff9b:1::/48"), IPNetwork.Parse("100::/64"), IPNetwork.Parse("2001::/23"),
        IPNetwork.Parse("2001:db8::/32"), IPNetwork.Parse("2002::/16"), IPNetwork.Parse("fc00::/7"),
        IPNetwork.Parse("fe80::/10"),
    ];
    private static readonly IPNetwork[] PublicIpv6Exceptions =
    [
        IPNetwork.Parse("2001:1::1/128"), IPNetwork.Parse("2001:1::2/128"), IPNetwork.Parse("2001:3::/32"),
        IPNetwork.Parse("2001:4:112::/48"), IPNetwork.Parse("2001:20::/28"), IPNetwork.Parse("2001:30::/28"),
    ];
    private static readonly IPNetwork Ipv4Multicast = IPNetwork.Parse("224.0.0.0/4");
    private static readonly IPNetwork[] ReservedIpv6 =
    [
        IPNetwork.Parse("::/8"), IPNetwork.Parse("100::/8"), IPNetwork.Parse("200::/7"),
        IPNetwork.Parse("400::/6"), IPNetwork.Parse("800::/5"), IPNetwork.Parse("1000::/4"),
        IPNetwork.Parse("4000::/3"), IPNetwork.Parse("6000::/3"), IPNetwork.Parse("8000::/3"),
        IPNetwork.Parse("a000::/3"), IPNetwork.Parse("c000::/3"), IPNetwork.Parse("e000::/4"),
        IPNetwork.Parse("f000::/5"), IPNetwork.Parse("f800::/6"), IPNetwork.Parse("fe00::/9"),
    ];
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
            if (!IsStrictIpv4Literal(value)) return false;
            return !PrivateIpv4.Any(network => network.Contains(address)
                    && !PublicIpv4Exceptions.Any(exception => exception.Contains(address)))
                && !Ipv4Multicast.Contains(address);
        }
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        return !address.IsIPv6Multicast
            && !ReservedIpv6.Any(network => network.Contains(address))
            && !PrivateIpv6.Any(network => network.Contains(address)
                && !PublicIpv6Exceptions.Any(exception => exception.Contains(address)));
    }

    private static bool IsStrictIpv4Literal(string value)
    {
        var octets = value.Split('.');
        return octets.Length == 4 && octets.All(octet =>
            octet.Length is > 0 and <= 3
            && (octet == "0" || octet[0] != '0')
            && byte.TryParse(octet, out _));
    }

    private static IocRule Rule(string category, string type, string pattern) =>
        new(category, type, new Regex(pattern, Options));

    private sealed record IocRule(string Category, string Type, Regex Pattern);
}
