using System.Text.Json;
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

public sealed class SiemTriageRequest
{
    [JsonPropertyName("events")]
    public List<SiemTriageEventRequest?>? Events { get; init; }

    public IReadOnlyList<SiemTriageEvent> ToEvents()
    {
        if (Events is not { Count: >= 1 and <= 50 })
        {
            throw new ArgumentException("Provide between 1 and 50 SIEM events.");
        }
        return Events.Select(item => item?.ToEvent()
            ?? throw new ArgumentException("SIEM events must be objects.")).ToArray();
    }
}

public sealed class SiemTriageEventRequest
{
    [JsonPropertyName("id")]
    public JsonElement? Id { get; init; }

    [JsonPropertyName("timestamp")]
    public string? Timestamp { get; init; }

    [JsonPropertyName("index_name")]
    public string? IndexName { get; init; }

    [JsonPropertyName("severity")]
    public JsonElement? Severity { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }

    [JsonPropertyName("source_ip")]
    public string? SourceIp { get; init; }

    [JsonPropertyName("event_category")]
    public string? EventCategory { get; init; }

    public SiemTriageEvent ToEvent()
    {
        CheckLength(Timestamp, "timestamp", 64);
        CheckLength(IndexName, "index_name", 256);
        CheckLength(Message, "message", 2000);
        CheckLength(SourceIp, "source_ip", 128);
        CheckLength(EventCategory, "event_category", 256);
        return new SiemTriageEvent(
            ReadScalar(Id, "id", allowDecimal: false),
            Timestamp,
            IndexName,
            ReadScalar(Severity, "severity", allowDecimal: true),
            Message,
            SourceIp,
            EventCategory);
    }

    private static string? ReadScalar(JsonElement? value, string field, bool allowDecimal)
    {
        if (value is null || value.Value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }
        var element = value.Value;
        if (element.ValueKind == JsonValueKind.String)
        {
            return element.GetString();
        }
        if (element.ValueKind == JsonValueKind.Number)
        {
            var raw = element.GetRawText();
            if (allowDecimal || raw.IndexOfAny(['.', 'e', 'E']) < 0)
            {
                return raw;
            }
        }
        throw new ArgumentException($"{field} must be text or a supported number.");
    }

    private static void CheckLength(string? value, string field, int maximum)
    {
        if (value is not null && value.Length > maximum)
        {
            throw new ArgumentException($"{field} must be no longer than {maximum} characters.");
        }
    }
}
