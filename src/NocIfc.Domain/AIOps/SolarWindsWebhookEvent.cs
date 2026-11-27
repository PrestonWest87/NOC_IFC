namespace NocIfc.Domain.AIOps;

public sealed record SolarWindsWebhookEvent(
    string NodeName,
    string IpAddress,
    string Severity,
    string AlertLevel,
    string EventType,
    string Status,
    bool IsResolution,
    string DeviceType,
    string SiteName,
    string Details);
