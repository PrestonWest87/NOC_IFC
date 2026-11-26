using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Settings;

namespace NocIfc.Application.Features.AIOps;

public sealed class AiopsRcaAnalysisEngine
{
    private static readonly IReadOnlyDictionary<string, int> DomainTiers = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["POWER_SUPPLIES"] = 1,
        ["INTERNET"] = 2,
        ["COMMS_EQUIPMENT"] = 3,
        ["COMPUTE"] = 4,
        ["RTU"] = 5,
        ["SCADA"] = 6,
        ["FACILITIES"] = 7,
        ["UNKNOWN_DOMAIN"] = 8,
    };

    private static readonly IReadOnlyDictionary<string, string[]> Ontology = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["INTERNET"] = ["VSAT", "Cellular", "Radio", "SD-WAN", "Modem", "ISP", "Internet"],
        ["COMMS_EQUIPMENT"] = ["Router", "Switch", "Firewall", "Lanolinx-switch", "Fabric Interconnect"],
        ["POWER_SUPPLIES"] = ["UPS", "Generator", "DC Power Supply", "PDU", "PDS", "DC Controller"],
        ["RTU"] = ["RTU"],
        ["SCADA"] = ["Sub Equipment", "Plant Equipment", "Meter Point", "I/O", "Member Equipment", "SCADA"],
        ["COMPUTE"] = ["VM Host", "VM Server", "Physical Machine", "Storage"],
        ["FACILITIES"] = ["Access Control Panel", "Door Controller", "IP Camera", "HVAC"],
    };

    private static readonly IReadOnlyDictionary<string, string[]> DomainAliases = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["INTERNET"] = ["INTERNET", "ISP", "WAN", "VSAT", "CELLULAR", "SD_WAN", "MODEM", "RADIO", "CARRIER", "SERVICE_PROVIDER", "TRANSPORT"],
        ["COMMS_EQUIPMENT"] = ["NETWORK_DEVICE", "NETWORK", "ROUTER", "SWITCH", "FIREWALL", "CISCO", "IOS", "PAN_OS", "PALO_ALTO", "WLC", "ACCESS_POINT", "WIRELESS", "IP_PHONE", "GARRETTCOM", "ZPE", "NTEST_RTU"],
        ["POWER_SUPPLIES"] = ["UPS", "PDU", "ATS", "GENERATOR", "BATTERY", "POWER", "DC_POWER", "HVAC"],
        ["RTU"] = ["RTU", "REMOTE_TERMINAL", "REMOTE_TERMINAL_UNIT"],
        ["SCADA"] = ["SCADA", "PLC", "METER", "SUBSTATION", "RELAY", "SEL", "OT", "ICS"],
        ["COMPUTE"] = ["COMPUTE", "SERVER", "HOST", "VM", "VM_HOST", "VM_SERVER", "STORAGE", "SAN", "NAS", "ESXI"],
        ["FACILITIES"] = ["FACILITIES", "FACILITY", "ACCESS_CONTROL", "DOOR_CONTROLLER", "IP_CAMERA", "BUILDING", "FIREALARM", "FIREALRAM", "PACS", "INTERCOM", "DATA_CENTER_A/C"],
    };

    public AiopsRcaAnalysisResult Analyze(
        IReadOnlyList<AiopsAlertEntry> activeAlerts,
        IReadOnlyList<AiopsTimelineEventEntry> events,
        IReadOnlyList<MonitoredLocationEntry> locations,
        AiopsRcaAnalysisContext context,
        bool canViewChronicInsights,
        DateTime nowUtc,
        bool includeFleetCorrelations = true)
    {
        var clusters = Cluster(activeAlerts, nowUtc);
        var fleetOutages = includeFleetCorrelations ? IdentifyFleetOutages(clusters) : [];
        var sites = locations.Where(location => !string.IsNullOrEmpty(location.Name))
            .GroupBy(location => location.Name!, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.Ordinal);
        var rootCauses = clusters.ToDictionary(
            pair => pair.Key,
            pair => CalculateRootCause(pair.Key, pair.Value, sites, context, fleetOutages),
            StringComparer.Ordinal);
        var chronicInsights = canViewChronicInsights ? GenerateChronicInsights(context.RecentAlerts) : null;
        return new AiopsRcaAnalysisResult(
            clusters, fleetOutages, rootCauses, events, canViewChronicInsights, chronicInsights,
            context.CloudOutages.Count, context.ActiveWeather.Count);
    }

    public static string? NormalizeDomainHint(string? value)
    {
        var normalized = Regex.Replace((value ?? "").Trim().ToUpperInvariant(), @"[\s-]+", "_");
        if (normalized == "PRIMARY_INTERNET") return "INTERNET";
        if (normalized == "UNKNOWN_DOMAIN") return normalized;
        if (DomainTiers.ContainsKey(normalized)) return normalized;

        foreach (var (domain, values) in DomainAliases)
        {
            if (values.Any(alias => normalized.Contains(alias, StringComparison.Ordinal))) return domain;
        }
        return null;
    }

    private static IReadOnlyDictionary<string, AiopsRcaCluster> Cluster(
        IReadOnlyList<AiopsAlertEntry> alerts,
        DateTime nowUtc)
    {
        var builders = new Dictionary<string, ClusterBuilder>(StringComparer.Ordinal);
        foreach (var alert in alerts)
        {
            var payload = ParsePayload(alert.RawPayloadJson);
            var custom = GetObject(payload, "Custom_Properties_Universal");
            var metrics = GetObject(payload, "Performance_Metrics");
            var site = FirstTruthy(GetText(custom, "Site"), alert.MappedLocation) ?? "Unknown";
            if (!builders.TryGetValue(site, out var builder))
            {
                builder = new ClusterBuilder(new AiopsRcaSiteMetadata(
                    FirstTruthy(GetText(custom, "Primary_Comms")) ?? "Unknown",
                    FirstTruthy(GetText(custom, "Secondary_Comms")) ?? "Unknown",
                    FirstTruthy(GetText(custom, "District")) ?? "Unknown"));
                builder.LatestAlert = alert;
                builders.Add(site, builder);
            }

            builder.Alerts.Add(alert);
            if (alert.ReceivedAt is not null
                && builder.LatestAlert?.ReceivedAt is { } latestReceivedAt
                && alert.ReceivedAt > latestReceivedAt)
            {
                builder.LatestAlert = alert;
            }
            if (TryMeasurement(GetText(metrics, "PercentLoss"), out var loss)) builder.AverageLoss.Add(loss);
            if (TryMeasurement(GetText(metrics, "CPULoad"), out var cpu)) builder.AverageCpu.Add(cpu);
            if (!string.IsNullOrEmpty(alert.IpAddress) && alert.IpAddress != "Unknown") builder.Ips.Add(alert.IpAddress);

            var alertLevel = FirstTruthy(
                GetText(payload, "Normalized_Alert_Level"),
                GetText(custom, "Alert_Level"),
                GetText(payload, "severity"));
            if (alertLevel is not null)
            {
                var levelMatch = Regex.Match(alertLevel, @"\d+");
                if (levelMatch.Success && int.TryParse(levelMatch.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var level))
                {
                    builder.MaximumAlertLevel = Math.Min(builder.MaximumAlertLevel, level);
                }
            }
        }

        var result = new Dictionary<string, AiopsRcaCluster>(StringComparer.Ordinal);
        foreach (var (site, builder) in builders)
        {
            var chain = DeterminePatientZero(builder.Alerts, nowUtc);
            result.Add(site, new AiopsRcaCluster(
                builder.Alerts.ToArray(),
                builder.SiteMetadata,
                chain.Select(item => item.Domain).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
                chain,
                builder.AverageLoss.ToArray(),
                builder.AverageCpu.ToArray(),
                builder.Ips.ToArray(),
                builder.MaximumAlertLevel,
                builder.LatestAlert ?? builder.Alerts.FirstOrDefault(),
                chain.FirstOrDefault()?.Alert));
        }
        return result;
    }

    private static IReadOnlyList<AiopsRcaDependencyEntry> DeterminePatientZero(
        IReadOnlyList<AiopsAlertEntry> alerts,
        DateTime nowUtc)
    {
        if (alerts.Count == 0) return [];
        var earliest = alerts.Where(alert => alert.ReceivedAt is not null)
            .Select(alert => alert.ReceivedAt!.Value)
            .DefaultIfEmpty(nowUtc)
            .Min();
        return alerts.Select(alert =>
        {
            var payload = ParsePayload(alert.RawPayloadJson);
            var custom = GetObject(payload, "Custom_Properties_Universal");
            var nodeDetails = GetObject(payload, "Node_Details");
            var metrics = GetObject(payload, "Performance_Metrics");
            var nodeType = FirstTruthy(
                GetText(nodeDetails, "MachineType"),
                GetText(custom, "Node_Type"),
                alert.DeviceType) ?? "Unknown";
            var domain = GetDomain(nodeType, alert.NodeName ?? "", GetText(custom, "Primary_Comms") ?? "");
            var tier = DomainTiers.GetValueOrDefault(domain, 8);
            var topologyScore = (9 - tier) * 2000;
            var status = (alert.Status ?? "None").ToLowerInvariant();
            var eventCategory = (alert.EventCategory ?? "None").ToLowerInvariant();
            TryMeasurement(GetText(metrics, "PercentLoss"), out var loss);
            var severity = status.Contains("down", StringComparison.Ordinal)
                || loss == 100
                || eventCategory.Contains("offline", StringComparison.Ordinal)
                    ? 1000
                    : status.Contains("critical", StringComparison.Ordinal) || loss > 50
                        ? 500
                        : status.Contains("warning", StringComparison.Ordinal) ? 100 : 0;
            var timeOffset = alert.ReceivedAt is null ? 0 : (alert.ReceivedAt.Value - earliest).TotalSeconds;
            return new AiopsRcaDependencyEntry(
                alert, topologyScore + severity - Math.Min(timeOffset, 200), domain, nodeType, severity);
        }).OrderByDescending(item => item.Score).ToArray();
    }

    private static string GetDomain(string nodeType, string nodeName, string primaryComms)
    {
        var hinted = NormalizeDomainHint(nodeType);
        if (hinted is not null) return hinted;
        var nodeText = $"{nodeType} {nodeName}".ToLowerInvariant();
        if (new[] { "vsat", "cell", "cellular", "sd-wan", "isp", "modem" }.Any(nodeText.Contains)) return "INTERNET";
        if (new[] { "ups", "pds", "pdu", "dc controller", "generator", "dc power" }.Any(nodeText.Contains)) return "POWER_SUPPLIES";
        if (new[] { "router", "switch", "firewall" }.Any(nodeText.Contains))
        {
            return nodeText.Contains("internet", StringComparison.Ordinal)
                || (!string.IsNullOrEmpty(primaryComms) && nodeText.Contains(primaryComms, StringComparison.OrdinalIgnoreCase))
                ? "INTERNET"
                : "COMMS_EQUIPMENT";
        }
        if (nodeText.Contains("rtu", StringComparison.Ordinal)) return "RTU";
        if (new[] { "scada", "meter", "i/o", "plant equipment", "sub equipment" }.Any(nodeText.Contains)) return "SCADA";
        foreach (var (domain, types) in Ontology)
        {
            if (types.Any(type => nodeType.Contains(type, StringComparison.OrdinalIgnoreCase))) return domain;
        }
        return "UNKNOWN_DOMAIN";
    }

    private static IReadOnlyList<AiopsFleetEvent> IdentifyFleetOutages(
        IReadOnlyDictionary<string, AiopsRcaCluster> clusters)
    {
        var providers = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var (site, cluster) in clusters)
        {
            var provider = cluster.SiteMetadata.PrimaryComms;
            if (!providers.TryGetValue(provider, out var affectedSites))
            {
                affectedSites = [];
                providers.Add(provider, affectedSites);
            }
            if (cluster.DependencyChain.Any(alert => alert.Domain is "INTERNET" or "COMMS_EQUIPMENT"))
            {
                affectedSites.Add(site);
            }
        }
        return providers.Where(provider => provider.Value.Count >= 5 && provider.Key != "Unknown")
            .Select(provider => new AiopsFleetEvent(
                provider.Key, provider.Value.ToArray(), "Regional Provider Outage", "CRITICAL"))
            .ToArray();
    }

    private static AiopsRootCause CalculateRootCause(
        string siteName,
        AiopsRcaCluster cluster,
        IReadOnlyDictionary<string, MonitoredLocationEntry> locations,
        AiopsRcaAnalysisContext context,
        IReadOnlyList<AiopsFleetEvent> fleetOutages)
    {
        var averageLoss = cluster.AverageLoss.Count == 0 ? 0 : cluster.AverageLoss.Average();
        var domains = cluster.DomainsAffected.ToHashSet(StringComparer.Ordinal);
        var patientZero = cluster.PatientZero;
        var patientZeroDomain = cluster.DependencyChain.FirstOrDefault(item => item.Alert.Id == patientZero?.Id)?.Domain ?? "UNKNOWN_DOMAIN";
        var score = 0;
        var evidence = new List<string>();
        if (patientZero is null)
        {
            return new AiopsRootCause("Indeterminate Failure", score, "P3 - MODERATE", evidence, "Unknown", "Unknown", "N/A");
        }

        if (domains.Count > 1)
        {
            score += 20;
            evidence.Add($"Dependency Cascade: Primary failure in [{patientZeroDomain}] triggered isolation of {cluster.Alerts.Count - 1} downstream devices.");
        }

        var cause = "Under Investigation";
        var fleetHit = false;
        foreach (var fleetEvent in fleetOutages)
        {
            if (!fleetEvent.AffectedSites.Contains(siteName, StringComparer.Ordinal)) continue;
            cause = $"Regional Carrier Outage ({fleetEvent.Provider})";
            score += 100;
            evidence.Add($"Fleet Correlation: Site is caught in a massive {fleetEvent.Provider} outage affecting {fleetEvent.AffectedSites.Count} total sites.");
            fleetHit = true;
            break;
        }

        var cloudHit = false;
        if (!fleetHit)
        {
            foreach (var alert in cluster.Alerts)
            {
                var payload = alert.RawPayloadJson ?? "";
                foreach (var outage in context.CloudOutages)
                {
                    var provider = outage.Provider?.ToLowerInvariant();
                    if (string.IsNullOrEmpty(provider)) continue;
                    if (!(alert.NodeName ?? "").Contains(provider, StringComparison.OrdinalIgnoreCase)
                        && !payload.Contains(provider, StringComparison.OrdinalIgnoreCase)) continue;
                    cause = $"Upstream Cloud Dependency Failure ({outage.Provider})";
                    score += 85;
                    evidence.Add($"Cloud Correlation: Node relies on {outage.Provider}, which is currently experiencing a known outage.");
                    cloudHit = true;
                    break;
                }
                if (cloudHit) break;
            }
        }

        var bgpHit = false;
        if (!cloudHit && !fleetHit
            && (domains.Contains("INTERNET") || domains.Contains("COMMS_EQUIPMENT")
                || domains.Any(domain => domain.Contains("Service Provider", StringComparison.Ordinal))))
        {
            foreach (var anomaly in context.ActiveBgp)
            {
                if (string.IsNullOrEmpty(anomaly.Asn)
                    || (!cluster.SiteMetadata.PrimaryComms.Contains(anomaly.Asn, StringComparison.Ordinal)
                        && !cluster.SiteMetadata.SecondaryComms.Contains(anomaly.Asn, StringComparison.Ordinal))) continue;
                cause = $"Carrier Routing Anomaly (BGP Event on {anomaly.Asn})";
                score += 75;
                evidence.Add($"BGP Correlation: Transport provider {anomaly.Asn} is actively experiencing a global routing anomaly.");
                bgpHit = true;
                break;
            }
        }

        if (!cloudHit && !bgpHit && !fleetHit)
        {
            if (patientZeroDomain == "POWER_SUPPLIES")
            {
                cause = "Catastrophic Facilities/Power Failure causing complete site isolation.";
                score += 60;
                evidence.Add($"Structural Cause: Foundational Power/Environmental node ({patientZero.NodeName}) failed.");
            }
            else if (patientZeroDomain is "INTERNET" or "COMMS_EQUIPMENT")
            {
                if (averageLoss >= 80 || (patientZero.Status ?? "").Contains("down", StringComparison.OrdinalIgnoreCase))
                {
                    var transport = cluster.SiteMetadata.PrimaryComms.Trim();
                    var titleDomain = CultureInfo.InvariantCulture.TextInfo.ToTitleCase(
                        patientZeroDomain.Replace('_', ' ').ToLowerInvariant());
                    if (transport.Length == 0 || transport.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                    {
                        transport = titleDomain;
                    }
                    cause = $"Site Isolation. Hard down on {transport} ({titleDomain}) domain.";
                    score += 50;
                    evidence.Add($"Structural Cause: Core transport/comms equipment ({patientZero.NodeName}) severed communication path.");
                }
                else
                {
                    cause = $"Severe Transport Congestion ({averageLoss}% Packet Loss).";
                }
            }
            else if (patientZeroDomain is "SCADA" or "RTU")
            {
                cause = "Isolated OT/SCADA Telemetry Failure.";
                score += 30;
                evidence.Add($"Structural Cause: Field equipment ({patientZero.NodeName}) alarming while Core IT network remains structurally stable.");
            }
            else if (patientZeroDomain == "UNKNOWN_DOMAIN")
            {
                cause = $"Indeterminate Infrastructure Failure at {patientZero.NodeName}; node type was not classifiable.";
                evidence.Add($"Data Quality: Unable to classify node type for {patientZero.NodeName}; root-cause confidence is limited.");
            }
            else
            {
                cause = $"Generalized Infrastructure Degradation originating at {patientZero.NodeName}.";
            }
        }

        if (locations.TryGetValue(siteName, out var location)
            && location.Latitude is not null and not 0
            && location.Longitude is not null and not 0)
        {
            foreach (var hazard in context.ActiveWeather)
            {
                var hazardLocation = hazard.Location ?? "";
                if (!hazardLocation.Contains(cluster.SiteMetadata.District, StringComparison.OrdinalIgnoreCase)
                    && !hazardLocation.Contains(siteName, StringComparison.OrdinalIgnoreCase)) continue;
                var hazardType = hazard.HazardType ?? "Unknown";
                score += 40;
                evidence.Add($"Regional Correlation: Site intersects active {hazardType} warning zone.");
                if (patientZeroDomain is "POWER_SUPPLIES" or "INTERNET")
                {
                    cause = $"Severe Weather ({hazardType}) induced failure of Utility/Carrier.";
                }
                break;
            }
        }

        if (cluster.MaximumAlertLevel == 1)
        {
            score += 50;
            evidence.Add("Policy Override: Native Alert Level 1 detected.");
        }
        var maximumLevel = cluster.MaximumAlertLevel == 99 ? 3 : cluster.MaximumAlertLevel;
        var (basePriority, sla) = maximumLevel switch
        {
            1 => ("P1 - CRITICAL", "15 Minutes"),
            2 => ("P2 - HIGH", "1 Hour"),
            3 => ("P3 - MODERATE", "4 Hours"),
            4 => ("P4 - LOW", "24 Hours"),
            5 => ("P5 - PLANNING", "Best Effort"),
            6 => ("P6 - INFORMATIONAL", "Best Effort"),
            _ => ("P3 - MODERATE", "4 Hours"),
        };
        var cascadeSeconds = cluster.LatestAlert?.ReceivedAt is { } latest
            && patientZero.ReceivedAt is { } earliest
                ? (int)(latest - earliest).TotalSeconds
                : 0;
        return new AiopsRootCause(
            cause, Math.Min(score, 100), $"{basePriority} (SLA: {sla})", evidence,
            "Unknown", patientZero.NodeName ?? "Unknown", cascadeSeconds > 0 ? $"{cascadeSeconds}s" : "Simultaneous");
    }

    private static AiopsChronicInsights? GenerateChronicInsights(IReadOnlyList<AiopsHistoricalAlertEntry> alerts)
    {
        var nodeCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var nodeMetadata = new Dictionary<string, (string? DeviceType, string Site)>(StringComparer.Ordinal);
        var nodeOrder = new List<string>();
        var siteCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var siteOrder = new List<string>();
        foreach (var alert in alerts)
        {
            var payload = ParsePayload(alert.RawPayloadJson);
            var custom = GetObject(payload, "Custom_Properties_Universal");
            var site = FirstTruthy(GetText(custom, "Site"), alert.MappedLocation) ?? "Unknown";
            if ((alert.Status ?? "None").Contains("resolved", StringComparison.OrdinalIgnoreCase)) continue;
            if (alert.NodeName is not null)
            {
                if (!nodeCounts.ContainsKey(alert.NodeName))
                {
                    nodeOrder.Add(alert.NodeName);
                    nodeMetadata.Add(alert.NodeName, (alert.DeviceType, site));
                    nodeCounts.Add(alert.NodeName, 0);
                }
                nodeCounts[alert.NodeName]++;
            }
            if (site != "Unknown")
            {
                if (!siteCounts.ContainsKey(site))
                {
                    siteOrder.Add(site);
                    siteCounts.Add(site, 0);
                }
                siteCounts[site]++;
            }
        }
        if (nodeCounts.Count == 0 && siteCounts.Count == 0) return null;

        var nodes = nodeOrder.OrderByDescending(node => nodeCounts[node]).Take(15)
            .Select(node => new AiopsChronicNodeSummary(node, nodeCounts[node], nodeMetadata[node].DeviceType, nodeMetadata[node].Site))
            .ToArray();
        var sites = siteOrder.OrderByDescending(site => siteCounts[site]).Take(10)
            .Select(site => new AiopsChronicSiteSummary(site, siteCounts[site]))
            .ToArray();
        var forecast = new List<string>();
        if (nodes.FirstOrDefault() is { IncidentCount: > 5 } topNode)
        {
            forecast.Add($"[CRITICAL] **CRITICAL FLAP DETECTED:** Node `{topNode.NodeName}` is exhibiting severe chronic instability with {topNode.IncidentCount} logged incidents this week. Recommend immediate hardware diagnostic or circuit test.");
        }
        if (sites.FirstOrDefault() is { IncidentCount: > 15 } topSite)
        {
            forecast.Add($"[HIGH] **REGIONAL DEGRADATION:** The `{topSite.Site}` facility is a current infrastructure hotspot. Recommend dispatching field tech to review local power conditioning and physical transport handoffs.");
        }
        if (forecast.Count == 0)
        {
            forecast.Add("[OK] Telemetry indicates normal operational limits. Devices are stable and no immediate predictive maintenance is required.");
        }
        return new AiopsChronicInsights(nodes, sites, forecast);
    }

    private static JsonElement ParsePayload(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return default;
        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : default;
        }
        catch (JsonException)
        {
            return default;
        }
    }

    private static JsonElement GetObject(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object
        && element.TryGetProperty(property, out var value)
        && value.ValueKind == JsonValueKind.Object
            ? value
            : default;

    private static string? GetText(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
            ? PythonText(value)
            : null;

    private static string? PythonText(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.GetRawText(),
        JsonValueKind.True => "True",
        JsonValueKind.False => "False",
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        _ => value.GetRawText(),
    };

    private static string? FirstTruthy(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrEmpty(value));

    private static bool TryMeasurement(string? value, out double number)
    {
        var normalized = (value ?? "0").Replace("%", "", StringComparison.Ordinal).Trim();
        return double.TryParse(normalized, NumberStyles.Float, CultureInfo.InvariantCulture, out number)
            && double.IsFinite(number);
    }

    private sealed class ClusterBuilder(AiopsRcaSiteMetadata siteMetadata)
    {
        public List<AiopsAlertEntry> Alerts { get; } = [];
        public AiopsRcaSiteMetadata SiteMetadata { get; } = siteMetadata;
        public List<double> AverageLoss { get; } = [];
        public List<double> AverageCpu { get; } = [];
        public List<string> Ips { get; } = [];
        public int MaximumAlertLevel { get; set; } = 99;
        public AiopsAlertEntry? LatestAlert { get; set; }
    }
}
