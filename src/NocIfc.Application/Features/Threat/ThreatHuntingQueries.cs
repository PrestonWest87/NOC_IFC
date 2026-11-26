using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed record ThreatHuntingSource(string? Link, string? Title);

public sealed record ThreatHuntingIoc(
    string Type,
    string? Indicator,
    string? Context,
    string Detected,
    string SourceArticle,
    IReadOnlyList<ThreatHuntingSource> Sources,
    int ArticleCount);

public sealed class ThreatHuntingQueries(IThreatHuntingStore hunting)
{
    private static readonly Regex SearchRegex = new("\"([^\"\\r\\n]+)\"|([^,;\\s]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex HashRegex = new("^[a-fA-F0-9]+$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex Ipv4TextRegex = new("^[0-9]{1,3}(?:\\.[0-9]{1,3}){3}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex DomainRegex = new("(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,63}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex CveRegex = new("^CVE-[0-9]{4}-[0-9]{4,7}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex MitreRegex = new("^T[0-9]{4}(?:\\.[0-9]{3})?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<IReadOnlyList<ThreatHuntingIoc>> GetIocsAsync(
        int daysBack,
        int limit,
        CancellationToken cancellationToken)
    {
        if (daysBack is < 1 or > 30)
        {
            throw new ArgumentOutOfRangeException(nameof(daysBack), "days_back must be between 1 and 30.");
        }
        if (limit is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(limit), "limit must be between 1 and 1000.");
        }

        var rows = await hunting.GetRecentIocsAsync(
            DateTime.UtcNow.AddDays(-daysBack), limit, cancellationToken);
        var nonCve = new List<ThreatHuntingIoc>();
        var cveGroups = new Dictionary<string, (string? Indicator, string Context, string Detected, string Source, List<ThreatHuntingSource> Sources)>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var sourceLink = row.SourceLink ?? "Unknown";
            var sourceTitle = row.SourceTitle ?? "Unknown";
            var detected = FormatCentral(row.DetectedAt);
            if (row.IndicatorType == "CVE")
            {
                var key = row.IndicatorValue ?? "\0";
                if (!cveGroups.TryGetValue(key, out var group))
                {
                    group = (row.IndicatorValue, row.Context ?? "Context unavailable.", detected, sourceLink, []);
                }
                group.Sources.Add(new ThreatHuntingSource(sourceLink, sourceTitle));
                cveGroups[key] = group;
            }
            else
            {
                nonCve.Add(new ThreatHuntingIoc(
                    row.IndicatorType ?? "",
                    row.IndicatorValue,
                    row.Context,
                    detected,
                    sourceLink,
                    [new ThreatHuntingSource(sourceLink, sourceTitle)],
                    1));
            }
        }
        nonCve.AddRange(cveGroups.Values.Select(group => new ThreatHuntingIoc(
            "CVE", group.Indicator, group.Context, group.Detected, group.Source, group.Sources, group.Sources.Count)));
        return nonCve;
    }

    public async Task<IReadOnlyList<ThreatArticle>> SearchArticlesAsync(
        string target,
        int daysBack,
        CancellationToken cancellationToken)
    {
        if (daysBack is < 1 or > 30)
        {
            throw new ArgumentOutOfRangeException(nameof(daysBack), "days_back must be between 1 and 30.");
        }
        var terms = ParseSearchTerms(target);
        if (terms.Count == 0)
        {
            return [];
        }
        return await hunting.SearchArticlesAsync(
            DateTime.UtcNow.AddDays(-daysBack), terms, 30, cancellationToken);
    }

    public string? GetOsintPivotLink(string? type, string? rawValue)
    {
        var value = (rawValue ?? "").Trim();
        if (value.Length == 0 || value.Length > 512)
        {
            return null;
        }
        switch (type)
        {
            case "SHA256" when value.Length == 64 && HashRegex.IsMatch(value):
                return $"https://www.virustotal.com/gui/file/{value}";
            case "SHA1" when value.Length == 40 && HashRegex.IsMatch(value):
                return $"https://www.virustotal.com/gui/file/{value}";
            case "MD5" when value.Length == 32 && HashRegex.IsMatch(value):
                return $"https://www.virustotal.com/gui/file/{value}";
            case "IPv4" when Ipv4TextRegex.IsMatch(value)
                && IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork:
                return $"https://www.shodan.io/host/{Uri.EscapeDataString(value)}";
            case "Domain" when DomainRegex.IsMatch(value):
                return $"https://www.virustotal.com/gui/domain/{Uri.EscapeDataString(value)}";
            case "CVE" when CveRegex.IsMatch(value):
                return $"https://nvd.nist.gov/vuln/detail/{Uri.EscapeDataString(value.ToUpperInvariant())}";
            case "MITRE ATT&CK" when MitreRegex.IsMatch(value):
                return $"https://attack.mitre.org/techniques/{value.Replace('.', '/').ToUpperInvariant()}";
            default:
                return null;
        }
    }

    public Task<PagedElasticEvents> GetElasticEventsAsync(
        int hoursBack,
        int page,
        int pageSize,
        CancellationToken cancellationToken)
    {
        if (hoursBack is < 1 or > 168)
        {
            throw new ArgumentOutOfRangeException(nameof(hoursBack), "hours_back must be between 1 and 168.");
        }
        if (page < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(page), "page must be at least 1.");
        }
        if (pageSize is < 1 or > 500)
        {
            throw new ArgumentOutOfRangeException(nameof(pageSize), "page_size must be between 1 and 500.");
        }
        return hunting.GetElasticEventsAsync(
            DateTime.UtcNow.AddHours(-hoursBack), page, pageSize, hoursBack, cancellationToken);
    }

    private static IReadOnlyList<string> ParseSearchTerms(string? target)
    {
        var value = (target ?? "").Trim();
        if (value.Length == 0)
        {
            return [];
        }
        if (value.Length > 500)
        {
            throw new ArgumentException("Search input must be 500 characters or fewer.");
        }
        if (value.Count(character => character == '"') % 2 != 0)
        {
            throw new ArgumentException("Search phrases must use balanced quotation marks.");
        }
        var terms = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in SearchRegex.Matches(value))
        {
            var term = (match.Groups[1].Success ? match.Groups[1].Value : match.Groups[2].Value).Trim();
            if (term.Length > 0 && seen.Add(term))
            {
                terms.Add(term);
                if (terms.Count == 50)
                {
                    break;
                }
            }
        }
        return terms;
    }

    private static string FormatCentral(DateTime? timestamp)
    {
        if (timestamp is null)
        {
            return "Unknown";
        }
        var zone = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");
        var utc = DateTime.SpecifyKind(timestamp.Value, DateTimeKind.Utc);
        return TimeZoneInfo.ConvertTimeFromUtc(utc, zone).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
    }
}
