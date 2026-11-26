using System.Globalization;
using System.Text.Json.Serialization;
using NocIfc.Domain.Threat;

namespace NocIfc.Api.Contracts;

public sealed record CloudOutageResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("provider")] string? Provider,
    [property: JsonPropertyName("service")] string? Service,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("link")] string? Link,
    [property: JsonPropertyName("is_resolved")] bool? IsResolved,
    [property: JsonPropertyName("updated_at")] DateTime? UpdatedAt,
    [property: JsonPropertyName("external_id")] string? ExternalId,
    [property: JsonPropertyName("status_code")] string? StatusCode)
{
    public static CloudOutageResponse From(CloudOutageEntry outage) => new(
        outage.Id,
        outage.Provider,
        outage.Service,
        outage.Title,
        outage.Description,
        outage.Link,
        outage.IsResolved,
        outage.UpdatedAt,
        outage.ExternalId,
        outage.StatusCode);
}

public sealed record CrimeIncidentResponse(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("category")] string? Category,
    [property: JsonPropertyName("raw_title")] string? RawTitle,
    [property: JsonPropertyName("timestamp")] string? Timestamp,
    [property: JsonPropertyName("distance_miles")] double? DistanceMiles,
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("lat")] double? Latitude,
    [property: JsonPropertyName("lon")] double? Longitude)
{
    public static CrimeIncidentResponse From(CrimeIncidentEntry incident) => new(
        incident.Id,
        incident.Category,
        incident.RawTitle,
        ToUtcIso(incident.Timestamp),
        incident.DistanceMiles,
        incident.Severity,
        incident.Latitude,
        incident.Longitude);

    private static string? ToUtcIso(DateTime? value) => value is null
        ? null
        : value.Value.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public sealed record Microsoft365IncidentResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("service")] string Service,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("link")] string Link,
    [property: JsonPropertyName("status_code")] string StatusCode,
    [property: JsonPropertyName("status_label")] string StatusLabel,
    [property: JsonPropertyName("updated_at")] string? UpdatedAt)
{
    public static Microsoft365IncidentResponse From(Microsoft365ActiveIncident incident) => new(
        incident.Id,
        incident.Title,
        incident.Service,
        incident.Description,
        incident.Link,
        incident.StatusCode,
        incident.StatusLabel,
        incident.UpdatedAt);
}

public sealed record Microsoft365ServiceStatusResponse(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("status_label")] string StatusLabel,
    [property: JsonPropertyName("active_incidents")] IReadOnlyList<Microsoft365IncidentResponse> ActiveIncidents)
{
    public static Microsoft365ServiceStatusResponse From(Microsoft365ServiceStatus service) => new(
        service.Id,
        service.Name,
        service.Status,
        service.StatusLabel,
        service.ActiveIncidents.Select(Microsoft365IncidentResponse.From).ToArray());
}

public sealed record Microsoft365StatusResponse(
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("source_url")] string SourceUrl,
    [property: JsonPropertyName("feed_url")] string FeedUrl,
    [property: JsonPropertyName("feed_status")] string FeedStatus,
    [property: JsonPropertyName("last_attempt_at")] string? LastAttemptAt,
    [property: JsonPropertyName("last_success_at")] string? LastSuccessAt,
    [property: JsonPropertyName("last_duration_ms")] int? LastDurationMs,
    [property: JsonPropertyName("last_http_status")] int? LastHttpStatus,
    [property: JsonPropertyName("last_error")] string? LastError,
    [property: JsonPropertyName("stale_after_minutes")] int StaleAfterMinutes,
    [property: JsonPropertyName("services")] IReadOnlyList<Microsoft365ServiceStatusResponse> Services,
    [property: JsonPropertyName("active_incidents")] IReadOnlyList<Microsoft365IncidentResponse> ActiveIncidents)
{
    public static Microsoft365StatusResponse From(Microsoft365StatusReport report) => new(
        report.Source,
        report.SourceUrl,
        report.FeedUrl,
        report.FeedStatus,
        report.LastAttemptAt,
        report.LastSuccessAt,
        report.LastDurationMs,
        report.LastHttpStatus,
        report.LastError,
        report.StaleAfterMinutes,
        report.Services.Select(Microsoft365ServiceStatusResponse.From).ToArray(),
        report.ActiveIncidents.Select(Microsoft365IncidentResponse.From).ToArray());
}
