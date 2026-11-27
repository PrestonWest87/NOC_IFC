namespace NocIfc.Domain.Reporting;

public sealed record SavedReportEntry(
    int Id,
    string? Title,
    string? Author,
    string? Content,
    DateTime? CreatedAt);
