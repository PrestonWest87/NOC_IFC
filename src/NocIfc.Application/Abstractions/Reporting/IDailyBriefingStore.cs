using NocIfc.Domain.Reporting;

namespace NocIfc.Application.Abstractions.Reporting;

public interface IDailyBriefingStore
{
    Task<IReadOnlyList<DailyBriefingEntry>> GetAllAsync(CancellationToken cancellationToken);
    Task<DailyFusionInputs> GetGenerationInputsAsync(
        DateTime startUtc,
        DateTime endUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken);
    Task SaveAsync(DateTime reportDateLocal, string content, DateTime createdAtUtc, CancellationToken cancellationToken);
}
