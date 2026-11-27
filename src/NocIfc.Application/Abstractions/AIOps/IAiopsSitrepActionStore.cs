using NocIfc.Domain.AIOps;

namespace NocIfc.Application.Abstractions.AIOps;

public interface IAiopsSitrepActionStore
{
    Task<AiopsRollingBriefInputs> GetRollingBriefInputsAsync(
        DateTime sinceUtc,
        DateTime nowUtc,
        CancellationToken cancellationToken);
    Task SaveRollingSummaryAsync(string summary, DateTime savedAtUtc, CancellationToken cancellationToken);
}
