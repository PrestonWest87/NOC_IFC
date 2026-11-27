using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Abstractions.Reporting;

public interface ISavedReportStore
{
    Task<IReadOnlyList<SavedReportEntry>> GetAllAsync(CancellationToken cancellationToken);
    Task SaveAsync(string title, string author, string content, DateTime createdAtUtc, CancellationToken cancellationToken);
    Task DeleteAsync(int reportId, CancellationToken cancellationToken);
}
