using System.Text.Json.Serialization;
using NocIfc.Domain.Reporting;

namespace NocIfc.Api.Contracts;

public sealed class SaveReportRequest
{
    [JsonPropertyName("title")]
    public string? Title { get; init; } = "Untitled Report";

    [JsonPropertyName("author")]
    public string? Author { get; init; } = "Unknown";

    [JsonPropertyName("content")]
    public string? Content { get; init; } = "";
}

public sealed record SavedReportResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("title")] string? Title,
    [property: JsonPropertyName("author")] string? Author,
    [property: JsonPropertyName("content")] string? Content,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt)
{
    public static SavedReportResponse From(SavedReportEntry report) => new(
        report.Id, report.Title, report.Author, report.Content, report.CreatedAt);
}

public sealed record DailyBriefingResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("report_date")] DateTime? ReportDate,
    [property: JsonPropertyName("content")] string? Content,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt)
{
    public static DailyBriefingResponse From(DailyBriefingEntry briefing) => new(
        briefing.Id, briefing.ReportDate, briefing.Content, briefing.CreatedAt);
}
