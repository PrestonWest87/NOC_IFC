using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

public sealed record AiopsAlertResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("event_type")] string? EventType,
    [property: JsonPropertyName("severity")] string? Severity,
    [property: JsonPropertyName("node_name")] string? NodeName,
    [property: JsonPropertyName("ip_address")] string? IpAddress,
    [property: JsonPropertyName("status")] string? Status,
    [property: JsonPropertyName("sw_timestamp")] string? SwTimestamp,
    [property: JsonPropertyName("details")] string? Details,
    [property: JsonPropertyName("node_link")] string? NodeLink,
    [property: JsonPropertyName("raw_payload")] JsonNode? RawPayload,
    [property: JsonPropertyName("mapped_location")] string? MappedLocation,
    [property: JsonPropertyName("received_at")] DateTime? ReceivedAt,
    [property: JsonPropertyName("resolved_at")] DateTime? ResolvedAt,
    [property: JsonPropertyName("is_dispatched")] bool IsDispatched,
    [property: JsonPropertyName("is_ticketed")] bool IsTicketed,
    [property: JsonPropertyName("is_correlated")] bool IsCorrelated,
    [property: JsonPropertyName("needs_dispatch")] bool NeedsDispatch,
    [property: JsonPropertyName("ai_root_cause")] string? AiRootCause,
    [property: JsonPropertyName("device_type")] string? DeviceType,
    [property: JsonPropertyName("event_category")] string? EventCategory,
    [property: JsonPropertyName("acknowledged_by")] string? AcknowledgedBy,
    [property: JsonPropertyName("acknowledged_at")] DateTime? AcknowledgedAt,
    [property: JsonPropertyName("dispatched_by")] string? DispatchedBy,
    [property: JsonPropertyName("dispatched_at")] DateTime? DispatchedAt,
    [property: JsonPropertyName("onpage_sent_at")] DateTime? OnpageSentAt)
{
    public static AiopsAlertResponse From(AiopsAlertEntry alert) => new(
        alert.Id, alert.EventType, alert.Severity, alert.NodeName, alert.IpAddress, alert.Status,
        alert.SwTimestamp, alert.Details, alert.NodeLink, ParseJson(alert.RawPayloadJson), alert.MappedLocation,
        alert.ReceivedAt, alert.ResolvedAt, alert.IsDispatched, alert.IsTicketed, alert.IsCorrelated,
        alert.NeedsDispatch, alert.AiRootCause, alert.DeviceType, alert.EventCategory, alert.AcknowledgedBy,
        alert.AcknowledgedAt, alert.DispatchedBy, alert.DispatchedAt, alert.OnpageSentAt);

    private static JsonNode? ParseJson(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        try
        {
            return JsonNode.Parse(value);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

public sealed record AiopsTimelineEventResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("timestamp")] DateTime? Timestamp,
    [property: JsonPropertyName("source")] string? Source,
    [property: JsonPropertyName("event_type")] string? EventType,
    [property: JsonPropertyName("message")] string? Message,
    [property: JsonPropertyName("site_name")] string? SiteName)
{
    public static AiopsTimelineEventResponse From(AiopsTimelineEventEntry entry) => new(
        entry.Id, entry.Timestamp, entry.Source, entry.EventType, entry.Message, entry.SiteName);
}

public sealed record AiopsRegionalOutageResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("outage_type")] string? OutageType,
    [property: JsonPropertyName("provider")] string? Provider,
    [property: JsonPropertyName("description")] string? Description,
    [property: JsonPropertyName("affected_area")] string? AffectedArea,
    [property: JsonPropertyName("lat")] double? Latitude,
    [property: JsonPropertyName("lon")] double? Longitude,
    [property: JsonPropertyName("radius_km")] double RadiusKilometers,
    [property: JsonPropertyName("detected_at")] DateTime? DetectedAt,
    [property: JsonPropertyName("is_resolved")] bool IsResolved)
{
    public static AiopsRegionalOutageResponse From(AiopsRegionalOutageEntry outage) => new(
        outage.Id, outage.OutageType, outage.Provider, outage.Description, outage.AffectedArea,
        outage.Latitude, outage.Longitude, outage.RadiusKilometers, outage.DetectedAt, outage.IsResolved);
}

public sealed record AiopsSiteResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string? Name,
    [property: JsonPropertyName("lat")] double? Latitude,
    [property: JsonPropertyName("lon")] double? Longitude,
    [property: JsonPropertyName("type")] string? LocationType,
    [property: JsonPropertyName("district")] string? District,
    [property: JsonPropertyName("priority")] string? Priority,
    [property: JsonPropertyName("under_maintenance")] bool? UnderMaintenance)
{
    public static AiopsSiteResponse From(MonitoredLocationEntry location) => new(
        location.Id, location.Name, location.Latitude, location.Longitude, location.LocationType,
        location.District, location.Priority, location.UnderMaintenance);
}

public sealed record AiopsDashboardResponse(
    [property: JsonPropertyName("alerts")] IReadOnlyList<AiopsAlertResponse> Alerts,
    [property: JsonPropertyName("events")] IReadOnlyList<AiopsTimelineEventResponse> Events,
    [property: JsonPropertyName("grid")] IReadOnlyList<AiopsRegionalOutageResponse> Grid,
    [property: JsonPropertyName("alert_count")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? AlertCount,
    [property: JsonPropertyName("active_issue_counts")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyDictionary<string, int>? ActiveIssueCounts)
{
    public static AiopsDashboardResponse From(AiopsBoardSnapshot snapshot) => new(
        snapshot.Alerts.Select(AiopsAlertResponse.From).ToArray(),
        snapshot.Events.Select(AiopsTimelineEventResponse.From).ToArray(),
        snapshot.Grid.Select(AiopsRegionalOutageResponse.From).ToArray(),
        snapshot.IsAdministrator ? null : snapshot.Alerts.Count,
        snapshot.IsAdministrator ? null : snapshot.ActiveIssueCounts);
}

public sealed record RcaDashboardResponse(
    [property: JsonPropertyName("alerts")] IReadOnlyList<AiopsAlertResponse> Alerts,
    [property: JsonPropertyName("events")] IReadOnlyList<AiopsTimelineEventResponse> Events,
    [property: JsonPropertyName("grid")] IReadOnlyList<AiopsRegionalOutageResponse> Grid,
    [property: JsonPropertyName("active_issue_counts")] IReadOnlyDictionary<string, int> ActiveIssueCounts,
    [property: JsonPropertyName("locations")] IReadOnlyList<MonitoredLocationResponse> Locations,
    [property: JsonPropertyName("investigating_sites")] IReadOnlyList<string> InvestigatingSites)
{
    public static RcaDashboardResponse From(AiopsBoardSnapshot snapshot) => new(
        snapshot.Alerts.Select(AiopsAlertResponse.From).ToArray(),
        snapshot.Events.Select(AiopsTimelineEventResponse.From).ToArray(),
        snapshot.Grid.Select(AiopsRegionalOutageResponse.From).ToArray(),
        snapshot.ActiveIssueCounts,
        snapshot.Locations.Select(MonitoredLocationResponse.From).ToArray(),
        snapshot.InvestigatingSites);
}
