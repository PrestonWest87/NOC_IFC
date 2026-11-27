using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Infrastructure.Integrations.Threat;

public sealed class CloudStatusSyncClient(
    HttpClient httpClient,
    SqliteCloudStatusSyncStore store) : ICloudStatusSyncProvider
{
    private const int MaxResponseBytes = 4 * 1024 * 1024;
    private static readonly ProviderFeed[] Feeds =
    [
        new("AWS", "https://status.aws.amazon.com/rss/all.rss"),
        new("Google Cloud", "https://status.cloud.google.com/en/feed.atom"),
        new("Azure", "https://azurestatuscdn.azureedge.net/en-us/status/feed/"),
        new("Microsoft 365", "https://status.cloud.microsoft/api/feed/mac"),
        new("Cisco Umbrella", "https://status.umbrella.com/history.rss"),
        new("Cisco Webex", "https://status.webex.com/history.rss"),
        new("Cisco Meraki", "https://status.meraki.net/history.rss"),
        new("Cloudflare", "https://www.cloudflarestatus.com/history.rss"),
        new("GitHub", "https://www.githubstatus.com/history.rss"),
        new("Slack", "https://status.slack.com/feed/rss"),
        new("Zoom", "https://status.zoom.us/history.rss"),
        new("Atlassian", "https://developer.status.atlassian.com/history.rss"),
        new("Datadog", "https://status.datadoghq.com/history.rss"),
        new("PagerDuty", "https://status.pagerduty.com/history.rss"),
        new("Twilio", "https://status.twilio.com/history.rss"),
        new("Okta", "https://status.okta.com/history.rss"),
        new("Zscaler", "https://trust.zscaler.com/feed"),
        new("CrowdStrike", "https://status.crowdstrike.com/history.rss"),
        new("Mimecast", "https://status.meraki.net/history.rss"),
    ];
    private static readonly string[] ForeignIdentifiers =
    [
        "eu-", "ap-", "sa-", "af-", "me-", "ca-", "europe", "asia", "africa", "south america",
        "canada", "australia", "tokyo", "seoul", "mumbai", "singapore", "sydney", "london",
        "frankfurt", "paris", "ireland", "sao paulo", "bahrain", "cape town", "hong kong", "dublin",
    ];
    private static readonly (string Key, string Display)[] UsRegions =
    [
        ("us-east-1", "US-East (N. Virginia)"), ("us-east-2", "US-East (Ohio)"),
        ("us-west-1", "US-West (N. California)"), ("us-west-2", "US-West (Oregon)"),
        ("eastus", "US-East (Virginia)"), ("eastus2", "US-East (Virginia)"),
        ("westus", "US-West (California)"), ("westus2", "US-West (Washington)"),
        ("centralus", "US-Central (Iowa)"), ("southcentralus", "US-South Central (Texas)"),
        ("us-central1", "US-Central (Iowa)"), ("us-east1", "US-East (S. Carolina)"),
        ("us-east4", "US-East (N. Virginia)"), ("us-west1", "US-West (Oregon)"),
        ("us-west2", "US-West (Los Angeles)"), ("us-south1", "US-South (Texas)"),
    ];
    private static readonly string[] ResolvedKeywords = ["[RESOLVED]", "RESOLVED", "OPERATIONAL", "COMPLETED", "MITIGATED"];
    private static readonly string[] MaintenanceKeywords = ["maintenance", "scheduled", "upcoming", "update"];
    private static readonly string[] MaintenanceActiveKeywords = ["in progress", "started", "currently undergoing"];
    private static readonly HashSet<string> MicrosoftResolvedStatuses = new(
        ["serviceoperational", "servicerestored", "resolved", "postincidentreviewpublished", "falsepositive", "mitigated", "mitigatedexternal", "resolvedexternal"],
        StringComparer.Ordinal);
    private static readonly HashSet<string> MicrosoftActiveStatuses = new(
        ["investigating", "servicedegradation", "serviceinterruption", "restoringservice", "verifyingservice", "extendedrecovery", "investigationsuspended", "confirmed", "reported"],
        StringComparer.Ordinal);
    private static readonly Regex TitleSplit = new(@"\s*(?: - |: \| |\| )\s*", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex HtmlBreaks = new(
        @"(?i)<br\s*/?>|</(?:div|p|li|ul|ol)>|</h[1-6]>", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex HtmlTags = new("<[^>]*>", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex HorizontalWhitespace = new("[ \\t]+", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public async Task<CloudStatusSyncOutcome> SyncAsync(CancellationToken cancellationToken)
    {
        var startedAt = DateTime.UtcNow;
        var recentCutoff = startedAt.AddDays(-7);
        using var concurrency = new SemaphoreSlim(5);
        var fetched = await Task.WhenAll(Feeds.Select(async feed =>
        {
            await concurrency.WaitAsync(cancellationToken);
            try
            {
                return await FetchAsync(feed, cancellationToken);
            }
            finally
            {
                concurrency.Release();
            }
        }));

        var failedProviders = fetched.Where(result => result.Error is not null)
            .Select(result => result.Feed.Provider).ToList();
        var candidates = new List<CloudOutageEntry>();
        var filteredCount = 0;
        var microsoftResult = fetched.Single(result => result.Feed.Provider == "Microsoft 365");
        Microsoft365FeedState microsoftState;
        if (microsoftResult.Error is { } microsoftError)
        {
            microsoftState = new Microsoft365FeedState(
                startedAt,
                null,
                ElapsedMilliseconds(startedAt),
                microsoftResult.HttpStatus,
                MicrosoftFetchError(microsoftError));
        }
        else
        {
            microsoftState = new Microsoft365FeedState(startedAt, null, null, microsoftResult.HttpStatus, null);
        }

        foreach (var result in fetched)
        {
            if (result.Error is not null) continue;
            IReadOnlyList<FeedEntry> entries;
            try
            {
                entries = ParseFeed(result.Content!);
            }
            catch (Exception exception) when (exception is XmlException or InvalidDataException)
            {
                if (!failedProviders.Contains(result.Feed.Provider, StringComparer.Ordinal))
                {
                    failedProviders.Add(result.Feed.Provider);
                }
                if (result.Feed.Provider == "Microsoft 365")
                {
                    microsoftState = new Microsoft365FeedState(
                        startedAt, null, null, result.HttpStatus,
                        "Microsoft 365 status feed returned invalid XML.");
                }
                continue;
            }

            if (result.Feed.Provider == "Microsoft 365")
            {
                microsoftState = new Microsoft365FeedState(
                    startedAt, DateTime.UtcNow, ElapsedMilliseconds(startedAt), result.HttpStatus, null);
            }
            foreach (var entry in entries.Take(15))
            {
                if (entry.UpdatedAt < recentCutoff) continue;
                var title = entry.Title ?? "Unknown Alert";
                var description = entry.Description ?? "";
                if (result.Feed.Provider == "Microsoft 365")
                {
                    description = PlainFeedText(description);
                }
                else if (IsFutureMaintenance(title, description, startedAt)
                         || IsForeignRegion(title + " " + description))
                {
                    filteredCount++;
                    continue;
                }

                var (isResolved, statusCode) = ResolveStatus(result.Feed.Provider, entry, title, description);
                var service = ExtractServiceName(result.Feed.Provider, title);
                var regions = ExtractUsRegions(title + " " + description);
                if (regions.Count > 0 && result.Feed.Provider != "Microsoft 365")
                {
                    service += $" [{string.Join(", ", regions)}]";
                }
                var externalIdValue = entry.Id;
                var externalId = result.Feed.Provider == "Microsoft 365" && !string.IsNullOrEmpty(externalIdValue)
                    ? externalIdValue[..Math.Min(255, externalIdValue.Length)]
                    : null;
                candidates.Add(new CloudOutageEntry(
                    0,
                    result.Feed.Provider,
                    service,
                    title,
                    description,
                    entry.Link ?? "",
                    isResolved,
                    entry.UpdatedAt,
                    externalId,
                    statusCode.Length > 64 ? statusCode[..64] : statusCode));
            }
        }

        var saved = await store.ReconcileAsync(
            candidates, microsoftState, startedAt.AddDays(-3), cancellationToken);
        return new CloudStatusSyncOutcome(saved.AddedCount, saved.ResolvedCount, filteredCount, failedProviders);
    }

    private async Task<FetchResult> FetchAsync(ProviderFeed feed, CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, feed.Url);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/rss+xml"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/atom+xml"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xml"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/xml"));
            request.Headers.UserAgent.ParseAdd("NOC-IFC/2.0");
            using var response = await httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            var httpStatus = (int)response.StatusCode;
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                return new FetchResult(feed, null, httpStatus, $"HTTP {httpStatus}");
            }
            return new FetchResult(feed, await ReadBodyAsync(response, cancellationToken), httpStatus, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new FetchResult(feed, null, null, "timeout");
        }
        catch (Exception exception)
        {
            return new FetchResult(feed, null, null, exception.Message);
        }
    }

    private static IReadOnlyList<FeedEntry> ParseFeed(byte[] body)
    {
        using var stream = new MemoryStream(body);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxResponseBytes,
        });
        var document = XDocument.Load(reader);
        return document.Descendants()
            .Where(element => element.Name.LocalName is "item" or "entry")
            .Select(element => new FeedEntry(
                ChildValue(element, "title"),
                LinkValue(element),
                FirstChildValue(element, "summary", "description", "content"),
                ParseDate(FirstChildValue(element, "published", "updated", "pubDate", "date")),
                FirstChildValue(element, "status") ?? AttributeValue(element, "status"),
                FirstNonEmpty(ChildValue(element, "id"), ChildValue(element, "guid"))))
            .ToArray();
    }

    private static string? ChildValue(XElement element, string name) =>
        element.Elements().FirstOrDefault(child => child.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static string? FirstChildValue(XElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (ChildValue(element, name) is { } value) return value;
        }
        return null;
    }

    private static string? LinkValue(XElement element)
    {
        var links = element.Elements().Where(child => child.Name.LocalName.Equals("link", StringComparison.OrdinalIgnoreCase)).ToArray();
        var alternate = links.FirstOrDefault(link =>
            string.Equals((string?)link.Attribute("rel"), "alternate", StringComparison.OrdinalIgnoreCase));
        var selected = alternate ?? links.FirstOrDefault();
        return (string?)selected?.Attribute("href") ?? selected?.Value;
    }

    private static string? AttributeValue(XElement element, string name) =>
        (string?)element.Attributes().FirstOrDefault(attribute =>
            attribute.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase));

    private static DateTime ParseDate(string? value) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? DateTime.SpecifyKind(parsed.UtcDateTime, DateTimeKind.Unspecified)
            : DateTime.UtcNow;

    private static bool IsFutureMaintenance(string title, string description, DateTime now)
    {
        var text = (title + " " + description).ToLowerInvariant();
        if (!MaintenanceKeywords.Any(text.Contains) || MaintenanceActiveKeywords.Any(text.Contains)) return false;
        var dates = new[]
        {
            now.ToString("MMM dd", CultureInfo.InvariantCulture).ToLowerInvariant(),
            now.ToString("MMMM dd", CultureInfo.InvariantCulture).ToLowerInvariant(),
            now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            now.ToString("MM/dd/yyyy", CultureInfo.InvariantCulture),
        };
        return !dates.Any(text.Contains);
    }

    private static bool IsForeignRegion(string text)
    {
        var lower = text.ToLowerInvariant();
        var hasUsScope = new[] { "us-", "united states", "north america", "global", "all regions" }
            .Any(lower.Contains);
        return !hasUsScope && ForeignIdentifiers.Any(identifier =>
            Regex.IsMatch(lower, $@"\b{Regex.Escape(identifier)}", RegexOptions.CultureInvariant));
    }

    private static List<string> ExtractUsRegions(string text)
    {
        var lower = text.ToLowerInvariant();
        var regions = UsRegions.Where(region => lower.Contains(region.Key, StringComparison.OrdinalIgnoreCase))
            .Select(region => region.Display).Distinct(StringComparer.Ordinal).ToList();
        if (regions.Count == 0 && new[] { "us-", "united states", "north america" }.Any(lower.Contains))
        {
            regions.Add("US-General / Multi-Region");
        }
        return regions;
    }

    private static string ExtractServiceName(string provider, string title)
    {
        var cleanTitle = title.Replace("[Investigating]", "", StringComparison.Ordinal)
            .Replace("[Resolved]", "", StringComparison.Ordinal)
            .Replace("[Update]", "", StringComparison.Ordinal)
            .Trim();
        var parts = TitleSplit.Split(cleanTitle, 2);
        if (parts.Length > 1) return parts[0].Trim();
        return provider switch
        {
            "AWS" => "AWS Infrastructure",
            "Google Cloud" => "Google Cloud Platform",
            "Azure" => "Microsoft Azure",
            "Microsoft 365" => "Microsoft 365 Service Health",
            _ => "General/Multiple Services",
        };
    }

    private static (bool IsResolved, string StatusCode) ResolveStatus(
        string provider,
        FeedEntry entry,
        string title,
        string description)
    {
        if (provider == "Microsoft 365")
        {
            var code = new string((entry.Status ?? "").ToLowerInvariant().Where(character => character is >= 'a' and <= 'z').ToArray());
            if (MicrosoftResolvedStatuses.Contains(code)) return (true, code);
            if (MicrosoftActiveStatuses.Contains(code)) return (false, code);
        }
        var text = (title + " " + description).ToUpperInvariant();
        return (ResolvedKeywords.Any(text.Contains), (entry.Status ?? "")[..Math.Min(64, (entry.Status ?? "").Length)]);
    }

    private static string PlainFeedText(string value)
    {
        var text = HtmlBreaks.Replace(value, "\n");
        text = HtmlTags.Replace(text, " ");
        text = WebUtility.HtmlDecode(text);
        return HorizontalWhitespace.Replace(text, " ").Trim();
    }

    private static string? FirstNonEmpty(string? first, string? second) =>
        !string.IsNullOrEmpty(first) ? first : second;

    private static string MicrosoftFetchError(string error)
    {
        if (error == "timeout") return "Microsoft 365 status feed request timed out.";
        if (error.StartsWith("HTTP ", StringComparison.Ordinal)) return $"Microsoft 365 status feed returned {error[..Math.Min(32, error.Length)]}.";
        return "Microsoft 365 status feed request failed.";
    }

    private static int ElapsedMilliseconds(DateTime startedAt) =>
        (int)Math.Clamp((DateTime.UtcNow - startedAt).TotalMilliseconds, 0, int.MaxValue);

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is > MaxResponseBytes)
        {
            throw new InvalidDataException("Cloud status feed exceeded the 4 MB response limit.");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var count = await stream.ReadAsync(chunk, cancellationToken);
            if (count == 0) break;
            if (buffer.Length + count > MaxResponseBytes)
            {
                throw new InvalidDataException("Cloud status feed exceeded the 4 MB response limit.");
            }
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    private sealed record ProviderFeed(string Provider, string Url);
    private sealed record FetchResult(ProviderFeed Feed, byte[]? Content, int? HttpStatus, string? Error);
    private sealed record FeedEntry(string? Title, string? Link, string? Description, DateTime UpdatedAt, string? Status, string? Id);
}
