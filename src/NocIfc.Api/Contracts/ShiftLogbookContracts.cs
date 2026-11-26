using System.Text.Json.Serialization;
using NocIfc.Domain.Logbook;

namespace NocIfc.Api.Contracts;

public sealed record ShiftLogEntryResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("analyst")] string? Analyst,
    [property: JsonPropertyName("author_role")] string? AuthorRole,
    [property: JsonPropertyName("shift_date")] DateTime? ShiftDate,
    [property: JsonPropertyName("shift_period")] string? ShiftPeriod,
    [property: JsonPropertyName("content")] string? Content,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt,
    [property: JsonPropertyName("is_deleted")] bool IsDeleted)
{
    public static ShiftLogEntryResponse From(ShiftLogEntry entry) => new(
        entry.Id,
        entry.Analyst,
        entry.AuthorRole,
        entry.ShiftDate,
        entry.ShiftPeriod,
        entry.Content,
        entry.CreatedAt,
        entry.IsDeleted);
}

public sealed record ShiftLogbookRoleResponse([property: JsonPropertyName("name")] string Name);
