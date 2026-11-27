using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Features.Reporting;

public sealed class SavedReportCommands(ISavedReportStore reports)
{
    public Task<IReadOnlyList<SavedReportEntry>> GetAllAsync(CancellationToken cancellationToken) =>
        reports.GetAllAsync(cancellationToken);

    public Task SaveAsync(string? title, string? author, string? content, CancellationToken cancellationToken)
    {
        title ??= "Untitled Report";
        author ??= "Unknown";
        content ??= "";
        if (title.Length > 200 || author.Length > 120 || content.Length > 200_000)
        {
            throw new ArgumentException("Saved report fields exceed their maximum length.");
        }
        return reports.SaveAsync(title, author, content, DateTime.UtcNow, cancellationToken);
    }

    public Task DeleteAsync(int reportId, CancellationToken cancellationToken) =>
        reports.DeleteAsync(reportId, cancellationToken);
}
