using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Abstractions.Reporting;

public interface IDailyBriefingStore
{
    Task<IReadOnlyList<DailyBriefingEntry>> GetAllAsync(CancellationToken cancellationToken);
}
