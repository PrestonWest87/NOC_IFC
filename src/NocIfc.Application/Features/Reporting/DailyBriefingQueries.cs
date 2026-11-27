using NocIfc.Application.Abstractions.Reporting;
using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Features.Reporting;

public sealed class DailyBriefingQueries(IDailyBriefingStore briefings)
{
    public Task<IReadOnlyList<DailyBriefingEntry>> GetAllAsync(CancellationToken cancellationToken) =>
        briefings.GetAllAsync(cancellationToken);
}
