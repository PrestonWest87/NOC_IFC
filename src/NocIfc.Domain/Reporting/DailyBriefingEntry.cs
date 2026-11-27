namespace NocIfc.Domain.Reporting;

public sealed record DailyBriefingEntry(
    int Id,
    DateTime? ReportDate,
    string? Content,
    DateTime? CreatedAt);
