using System.Text.Json.Serialization;
using NocIfc.Application.Features.Threat;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed record ThreatHuntingSourceResponse(
    [property: JsonPropertyName("link")] string? Link,
    [property: JsonPropertyName("title")] string? Title)
{
    public static ThreatHuntingSourceResponse From(ThreatHuntingSource source) => new(source.Link, source.Title);
}

public sealed record ThreatHuntingIocResponse(
    [property: JsonPropertyName("Type")] string Type,
    [property: JsonPropertyName("Indicator")] string? Indicator,
    [property: JsonPropertyName("Context")] string? Context,
    [property: JsonPropertyName("Detected")] string Detected,
    [property: JsonPropertyName("Source Article")] string SourceArticle,
    [property: JsonPropertyName("sources")] IReadOnlyList<ThreatHuntingSourceResponse> Sources,
    [property: JsonPropertyName("article_count")] int ArticleCount)
{
    public static ThreatHuntingIocResponse From(ThreatHuntingIoc ioc) => new(
        ioc.Type,
        ioc.Indicator,
        ioc.Context,
        ioc.Detected,
        ioc.SourceArticle,
        ioc.Sources.Select(ThreatHuntingSourceResponse.From).ToArray(),
        ioc.ArticleCount);
}

public sealed record ElasticEventResponse(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("timestamp")] DateTime? Timestamp,
    [property: JsonPropertyName("index_name")] string? IndexName,
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("message")] string? Message,
    [property: JsonPropertyName("source_ip")] string? SourceIp,
    [property: JsonPropertyName("event_category")] string? EventCategory)
{
    public static ElasticEventResponse From(ElasticEventEntry entry) => new(
        entry.Id,
        entry.Timestamp,
        entry.IndexName,
        entry.Severity,
        entry.Message,
        entry.SourceIp,
        entry.EventCategory);
}

public sealed record ElasticEventsPageResponse(
    [property: JsonPropertyName("items")] IReadOnlyList<ElasticEventResponse> Items,
    [property: JsonPropertyName("total")] int Total,
    [property: JsonPropertyName("page")] int Page,
    [property: JsonPropertyName("page_size")] int PageSize,
    [property: JsonPropertyName("hours_back")] int HoursBack)
{
    public static ElasticEventsPageResponse From(PagedElasticEvents page) => new(
        page.Items.Select(ElasticEventResponse.From).ToArray(),
        page.Total,
        page.Page,
        page.PageSize,
        page.HoursBack);
}
