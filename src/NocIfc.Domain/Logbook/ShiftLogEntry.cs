namespace NocIfc.Domain.Logbook;

public sealed record ShiftLogEntry(
    int Id,
    string? Analyst,
    string? AuthorRole,
    DateTime? ShiftDate,
    string? ShiftPeriod,
    string? Content,
    DateTime? CreatedAt,
    bool IsDeleted);
