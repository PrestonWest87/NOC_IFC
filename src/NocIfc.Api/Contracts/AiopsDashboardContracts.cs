using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

public sealed class RcaDispatchRequest
{
    [JsonPropertyName("alert_ids")]
    public int[] AlertIds { get; init; } = [];

    [JsonPropertyName("is_dispatched")]
    public bool IsDispatched { get; init; } = true;
}

public sealed class RcaSendTicketRequest
{
    [JsonPropertyName("site")]
    public string? Site { get; init; }

    [JsonPropertyName("priority")]
    public string? Priority { get; init; } = "P3";

    [JsonPropertyName("ticket_text")]
    public string? TicketText { get; init; }

    [JsonPropertyName("recipient")]
    public string? Recipient { get; init; } = "remedyforceworkflow@aecc.com, noc@aecc.com";

    [JsonPropertyName("alert_ids")]
    public int[]? AlertIds { get; init; } = [];

    [JsonPropertyName("sla")]
    public string? Sla { get; init; } = "N/A (Manual Dispatch)";
}

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

public sealed record AiopsRcaDependencyResponse(
    [property: JsonPropertyName("alert")] AiopsAlertResponse Alert,
    [property: JsonPropertyName("score")] double Score,
    [property: JsonPropertyName("domain")] string Domain,
    [property: JsonPropertyName("node_type")] string NodeType,
    [property: JsonPropertyName("severity")] int Severity)
{
    public static AiopsRcaDependencyResponse From(AiopsRcaDependencyEntry entry) => new(
        AiopsAlertResponse.From(entry.Alert), entry.Score, entry.Domain, entry.NodeType, entry.Severity);
}

public sealed record AiopsRcaSiteMetadataResponse(
    [property: JsonPropertyName("primary_coms")] string PrimaryComms,
    [property: JsonPropertyName("secondary_coms")] string SecondaryComms,
    [property: JsonPropertyName("district")] string District)
{
    public static AiopsRcaSiteMetadataResponse From(AiopsRcaSiteMetadata metadata) => new(
        metadata.PrimaryComms, metadata.SecondaryComms, metadata.District);
}

public sealed record AiopsRcaClusterResponse(
    [property: JsonPropertyName("alerts")] IReadOnlyList<AiopsAlertResponse> Alerts,
    [property: JsonPropertyName("site_metadata")] AiopsRcaSiteMetadataResponse SiteMetadata,
    [property: JsonPropertyName("domains_affected")] IReadOnlyList<string> DomainsAffected,
    [property: JsonPropertyName("dependency_chain")] IReadOnlyList<AiopsRcaDependencyResponse> DependencyChain,
    [property: JsonPropertyName("avg_loss")] IReadOnlyList<double> AverageLoss,
    [property: JsonPropertyName("avg_cpu")] IReadOnlyList<double> AverageCpu,
    [property: JsonPropertyName("ips")] IReadOnlyList<string> Ips,
    [property: JsonPropertyName("max_alert_level")] int MaximumAlertLevel,
    [property: JsonPropertyName("latest_alert")] AiopsAlertResponse? LatestAlert,
    [property: JsonPropertyName("patient_zero")] AiopsAlertResponse? PatientZero)
{
    public static AiopsRcaClusterResponse From(AiopsRcaCluster cluster) => new(
        cluster.Alerts.Select(AiopsAlertResponse.From).ToArray(),
        AiopsRcaSiteMetadataResponse.From(cluster.SiteMetadata),
        cluster.DomainsAffected,
        cluster.DependencyChain.Select(AiopsRcaDependencyResponse.From).ToArray(),
        cluster.AverageLoss,
        cluster.AverageCpu,
        cluster.Ips,
        cluster.MaximumAlertLevel,
        cluster.LatestAlert is null ? null : AiopsAlertResponse.From(cluster.LatestAlert),
        cluster.PatientZero is null ? null : AiopsAlertResponse.From(cluster.PatientZero));
}

public sealed record AiopsFleetEventResponse(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("affected_sites")] IReadOnlyList<string> AffectedSites,
    [property: JsonPropertyName("event_type")] string EventType,
    [property: JsonPropertyName("severity")] string Severity)
{
    public static AiopsFleetEventResponse From(AiopsFleetEvent fleetEvent) => new(
        fleetEvent.Provider, fleetEvent.AffectedSites, fleetEvent.EventType, fleetEvent.Severity);
}

public sealed record AiopsChronicNodeResponse(
    [property: JsonPropertyName("Node Name")] string NodeName,
    [property: JsonPropertyName("Total Incidents (60 Days)")] int IncidentCount,
    [property: JsonPropertyName("Device Type")] string? DeviceType,
    [property: JsonPropertyName("Site")] string Site)
{
    public static AiopsChronicNodeResponse From(AiopsChronicNodeSummary summary) => new(
        summary.NodeName, summary.IncidentCount, summary.DeviceType, summary.Site);
}

public sealed record AiopsChronicSiteResponse(
    [property: JsonPropertyName("Site")] string Site,
    [property: JsonPropertyName("Total Incidents (60 Days)")] int IncidentCount)
{
    public static AiopsChronicSiteResponse From(AiopsChronicSiteSummary summary) => new(
        summary.Site, summary.IncidentCount);
}

public sealed record AiopsRcaAnalysisResponse(
    [property: JsonPropertyName("clustered")] IReadOnlyDictionary<string, AiopsRcaClusterResponse> Clustered,
    [property: JsonPropertyName("fleet_outages")] IReadOnlyList<AiopsFleetEventResponse> FleetOutages,
    [property: JsonPropertyName("root_cause")] IReadOnlyDictionary<string, object?[]> RootCause,
    [property: JsonPropertyName("chronic_insights")] object?[] ChronicInsights,
    [property: JsonPropertyName("events")] IReadOnlyList<AiopsTimelineEventResponse> Events)
{
    public static AiopsRcaAnalysisResponse From(AiopsRcaAnalysisResult result) => new(
        result.Clustered.ToDictionary(pair => pair.Key, pair => AiopsRcaClusterResponse.From(pair.Value), StringComparer.Ordinal),
        result.FleetOutages.Select(AiopsFleetEventResponse.From).ToArray(),
        result.RootCause.ToDictionary(
            pair => pair.Key,
            pair => new object?[]
            {
                pair.Value.Cause, pair.Value.Score, pair.Value.Priority, pair.Value.Evidence,
                pair.Value.BlastRadius, pair.Value.PatientZero, pair.Value.CascadeDelay,
            },
            StringComparer.Ordinal),
        result.CanViewChronicInsights
            ? result.ChronicInsights is null
                ? [null, null, null]
                :
                [
                    result.ChronicInsights.OffendingNodes.Select(AiopsChronicNodeResponse.From).ToArray(),
                    result.ChronicInsights.Hotspots.Select(AiopsChronicSiteResponse.From).ToArray(),
                    result.ChronicInsights.Forecast,
                ]
            : [],
        result.Events.Select(AiopsTimelineEventResponse.From).ToArray());
}
