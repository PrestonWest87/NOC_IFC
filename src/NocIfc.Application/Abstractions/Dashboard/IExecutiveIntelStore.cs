using NocIfc.Domain.Dashboard;

namespace NocIfc.Application.Abstractions.Dashboard;

public interface IExecutiveIntelStore
{
    Task<ExecutiveIntelInputs> GetInputsAsync(DateTime sinceUtc, DateTime nowUtc, CancellationToken cancellationToken);
    Task<IReadOnlyList<NocIfc.Domain.Threat.ThreatArticle>> GetRecentScoredArticlesAsync(
        DateTime sinceUtc,
        int limit,
        CancellationToken cancellationToken);
    Task SaveDailyThreatScoreAsync(
        DateTime recordDateUtc,
        int cyberPoints,
        int physicalPoints,
        double cyberBaseline,
        double physicalBaseline,
        CancellationToken cancellationToken);
}
