using System.Globalization;
using System.Text;

namespace NocIfc.Application.Features.AIOps;

public sealed record AiopsTicketTextAlert(
    string? ReceivedAt,
    string NodeName,
    string IpAddress,
    string Status,
    string EventCategory);

public sealed record AiopsTicketTextInput(
    string Site,
    string? Priority,
    string? RootCause,
    string? PatientZeroReceivedAt,
    string District,
    IReadOnlyList<string> DomainsAffected,
    IReadOnlyList<AiopsTicketTextAlert> Alerts);

public static class AiopsRcaTicketTextGenerator
{
    private static readonly TimeZoneInfo CentralTime = TimeZoneInfo.FindSystemTimeZoneById("America/Chicago");

    public static string Generate(AiopsTicketTextInput input)
    {
        var priority = SanitizeText(input.Priority ?? "");
        var rootCause = SanitizeText(input.RootCause ?? "");
        var triggerTime = FormatTriggerTime(input.PatientZeroReceivedAt);
        var domains = input.DomainsAffected.Count == 0
            ? "SCADA connectivity"
            : string.Join(", ", input.DomainsAffected.Select(domain =>
                CultureInfo.InvariantCulture.TextInfo.ToTitleCase(domain.ToLowerInvariant()).Replace('_', ' ')));
        var text = new StringBuilder(
            $"Automated Comms Outage\nDistrict: {input.District}\n\n{input.Site} - Trouble\n\n" +
            $"A communications issue was identified on {triggerTime}. This is affecting {domains}. For more information, please see additional notes.\n\n");
        text.Append($"\nPRIORITY: {priority}\n{rootCause}\n\nAFFECTED INFRASTRUCTURE DETAILS:\n");
        for (var index = 0; index < input.Alerts.Count; index++)
        {
            var alert = input.Alerts[index];
            text.Append('[').Append(index + 1).Append("] ")
                .Append(alert.NodeName).Append(" (").Append(alert.IpAddress).Append(") - ")
                .Append(alert.Status).Append(" | ").Append(alert.EventCategory).Append(" | Since: ")
                .Append(FormatCentral(alert.ReceivedAt)).Append('\n');
        }
        return text.ToString();
    }

    private static string FormatTriggerTime(string? timestamp)
    {
        if (string.IsNullOrEmpty(timestamp)) return "Unknown Time";
        if (!TryParseTimestamp(timestamp, out var parsed)) return "Unknown Time";
        var local = TimeZoneInfo.ConvertTime(parsed, CentralTime);
        var abbreviation = local.Offset == TimeSpan.FromHours(-5) ? "CDT" : "CST";
        return $"{local.ToString("MM/dd/yyyy hh:mm tt", CultureInfo.InvariantCulture)} {abbreviation}";
    }

    private static string FormatCentral(string? timestamp)
    {
        if (string.IsNullOrEmpty(timestamp)) return "Unknown";
        if (!TryParseTimestamp(timestamp, out var parsed)) return timestamp;
        return TimeZoneInfo.ConvertTime(parsed, CentralTime).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
    }

    private static bool TryParseTimestamp(string value, out DateTimeOffset timestamp) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);

    private static string SanitizeText(string value)
    {
        var result = new StringBuilder(value.Length);
        foreach (var rune in value.EnumerateRunes())
        {
            if (rune.Value <= 0xffff && rune.Value != '?') result.Append(rune.ToString());
        }
        return result.ToString().Trim();
    }
}
