using System.Text.Json.Serialization;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed class KeywordWeightUpdateRequest
{
    [JsonPropertyName("weight")]
    public int? Weight { get; init; }
}

public sealed record KeywordDirectoryResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("word")] string Word,
    [property: JsonPropertyName("weight")] int? Weight)
{
    public static KeywordDirectoryResponse From(KeywordDirectoryEntry keyword) =>
        new(keyword.Id, keyword.Word, keyword.Weight);
}

public sealed record FeedSourceResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("url")] string? Url,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("is_active")] bool? IsActive)
{
    public static FeedSourceResponse From(FeedSourceEntry feed) =>
        new(feed.Id, feed.Url, feed.Name, feed.IsActive);
}

public sealed record RssSettingsResponse(
    [property: JsonPropertyName("keywords")] IReadOnlyList<KeywordDirectoryResponse> Keywords,
    [property: JsonPropertyName("feeds")] IReadOnlyList<FeedSourceResponse> Feeds)
{
    public static RssSettingsResponse From(RssSettingsCatalog catalog) => new(
        catalog.Keywords.Select(KeywordDirectoryResponse.From).ToArray(),
        catalog.Feeds.Select(FeedSourceResponse.From).ToArray());
}

public sealed record KeywordWeightUpdateResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("keyword")] KeywordDirectoryResponse Keyword);
