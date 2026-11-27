using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using NocIfc.Application.Abstractions.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Application.Features.Threat;

public sealed record RssFeedFetchOutcome(int AddedCount, int FailedFeeds, int RemovedDuplicates);

public sealed class RssFeedFetchCommands(
    IRssSettingsStore settings,
    IRssFeedClient feedClient,
    IRssIngestionStore articles)
{
    private const int FetchChunkSize = 5;
    private const int MaxFeedBytes = 8 * 1024 * 1024;

    public async Task<RssFeedFetchOutcome> ExecuteAsync(CancellationToken cancellationToken)
    {
        var catalog = await settings.GetCatalogAsync(cancellationToken);
        var feeds = catalog.Feeds.Where(feed => feed.IsActive == true).ToArray();
        if (feeds.Length == 0) return new RssFeedFetchOutcome(0, 0, 0);

        var now = DateTime.UtcNow;
        var knownLinks = (await articles.GetRecentLinksAsync(now.AddDays(-7), cancellationToken))
            .ToHashSet(StringComparer.Ordinal);
        var weights = catalog.Keywords.OrderBy(keyword => keyword.Id)
            .Where(keyword => !string.IsNullOrEmpty(keyword.Word))
            .Select(keyword => new KeywordWeight(keyword.Word, keyword.Weight ?? 0))
            .ToArray();
        var candidates = new List<RssArticleIngestCandidate>();
        var failedFeeds = 0;

        foreach (var chunk in feeds.Chunk(FetchChunkSize))
        {
            var downloads = await Task.WhenAll(chunk.Select(async feed =>
                (Feed: feed, Content: await feedClient.FetchAsync(feed.Url, cancellationToken))));
            foreach (var download in downloads)
            {
                if (download.Content is null)
                {
                    failedFeeds++;
                    continue;
                }
                try
                {
                    candidates.AddRange(ParseAndScore(
                        download.Feed.Name ?? "Unknown Feed", download.Content, knownLinks, weights));
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception)
                {
                    failedFeeds++;
                }
            }
            if (chunk.Length == FetchChunkSize && feeds.Length > FetchChunkSize)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
            }
        }

        var added = await articles.InsertArticlesAsync(candidates, cancellationToken);
        var removed = await articles.DeduplicateRecentArticlesAsync(DateTime.UtcNow.AddHours(-24), cancellationToken);
        return new RssFeedFetchOutcome(added, failedFeeds, removed);
    }

    private static IReadOnlyList<RssArticleIngestCandidate> ParseAndScore(
        string feedName,
        byte[] content,
        IReadOnlySet<string> knownLinks,
        IReadOnlyList<KeywordWeight> weights)
    {
        if (content.Length > MaxFeedBytes) throw new InvalidDataException("RSS feed exceeded the 8 MB response limit.");
        using var stream = new MemoryStream(content);
        using var reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxFeedBytes,
        });
        var document = XDocument.Load(reader);
        var candidates = new List<RssArticleIngestCandidate>();
        var seenInFeed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in document.Descendants().Where(element =>
                     element.Name.LocalName is "item" or "entry"))
        {
            var link = ReadLink(entry);
            if (string.IsNullOrEmpty(link) || knownLinks.Contains(link) || !seenInFeed.Add(link)) continue;
            var title = ChildValue(entry, "title") ?? "";
            var summary = FirstChildValue(entry, "summary", "description", "content", "encoded") ?? "";
            var text = $"{title} {summary}";
            var score = KeywordScorer.Score(text, weights);
            var category = ArticleCategorizer.CategorizeText(text);
            var iocs = score.Score >= 50 && category.StartsWith("Cyber", StringComparison.Ordinal)
                ? EnterpriseIocExtractor.Extract(text)
                : [];
            candidates.Add(new RssArticleIngestCandidate(
                title,
                link,
                summary,
                feedName,
                ReadPublishedDate(entry),
                score.Score,
                category,
                score.Reasons,
                score.Score >= 45,
                iocs));
        }
        return candidates;
    }

    private static string? ReadLink(XElement entry)
    {
        var links = entry.Elements().Where(element =>
            element.Name.LocalName.Equals("link", StringComparison.OrdinalIgnoreCase)).ToArray();
        var alternate = links.FirstOrDefault(element =>
            string.Equals((string?)element.Attribute("rel"), "alternate", StringComparison.OrdinalIgnoreCase));
        var selected = alternate ?? links.FirstOrDefault();
        return (string?)selected?.Attribute("href") ?? selected?.Value;
    }

    private static string? ChildValue(XElement element, string name) =>
        element.Elements().FirstOrDefault(child =>
            child.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

    private static string? FirstChildValue(XElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (ChildValue(element, name) is { } value) return value;
        }
        return null;
    }

    private static DateTime ReadPublishedDate(XElement entry)
    {
        var value = FirstChildValue(entry, "published", "updated", "pubDate", "date");
        return DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)
            ? DateTime.SpecifyKind(parsed.UtcDateTime, DateTimeKind.Unspecified)
            : DateTime.UtcNow;
    }
}
