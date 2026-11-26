namespace NocIfc.Domain.Threat;

public sealed record KeywordDirectoryEntry(int Id, string Word, int? Weight);

public sealed record FeedSourceEntry(int Id, string? Url, string? Name, bool? IsActive);

public sealed record RssSettingsCatalog(
    IReadOnlyList<KeywordDirectoryEntry> Keywords,
    IReadOnlyList<FeedSourceEntry> Feeds);
