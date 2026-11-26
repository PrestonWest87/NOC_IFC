using NocIfc.Domain.Logbook;

namespace NocIfc.Application.Abstractions.Logbook;

public interface IShiftLogbookStore
{
    Task<IReadOnlyList<ShiftLogEntry>> GetEntriesAsync(
        string? roleFilter,
        DateTime? startUtc,
        DateTime? endExclusiveUtc,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<ShiftLogEntry>> GetSummaryEntriesAsync(
        string? roleFilter,
        string? shiftPeriod,
        bool excludeGeneratedSummaries,
        DateTime startUtc,
        DateTime endExclusiveUtc,
        int limit,
        CancellationToken cancellationToken);
    Task<IReadOnlyList<string>> GetRoleNamesAsync(CancellationToken cancellationToken);
    Task<string?> GetUserFullNameAsync(int userId, CancellationToken cancellationToken);
    Task<int> CreateAsync(
        string analyst,
        string authorRole,
        string shiftPeriod,
        string content,
        DateTime createdAtUtc,
        DateTime shiftDateUtc,
        CancellationToken cancellationToken);
    Task<ShiftLogEntry?> GetByIdAsync(int entryId, CancellationToken cancellationToken);
    Task<bool> SetDeletedAsync(int entryId, bool isDeleted, CancellationToken cancellationToken);
}
