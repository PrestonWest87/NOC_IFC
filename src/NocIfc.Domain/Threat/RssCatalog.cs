namespace NocIfc.Domain.Threat;

public sealed record KeywordDirectoryEntry(int Id, string Word, int? Weight);

public sealed record FeedSourceEntry(int Id, string? Url, string? Name, bool? IsActive);

public sealed record RssSettingsCatalog(
    IReadOnlyList<KeywordDirectoryEntry> Keywords,
    IReadOnlyList<FeedSourceEntry> Feeds);

public sealed record RssArticleIoc(string Category, string Type, string Indicator, string Context);

public sealed record RssArticleIngestCandidate(
    string? Title,
    string Link,
    string? Summary,
    string? Source,
    DateTime PublishedDateUtc,
    double Score,
    string Category,
    IReadOnlyList<string> KeywordsFound,
    bool IsBubbled,
    IReadOnlyList<RssArticleIoc> Iocs);
