using NocIfc.Domain.AIOps;

namespace NocIfc.Application.Abstractions.AIOps;

public interface IAiopsRcaAnalysisStore
{
    Task<AiopsRcaAnalysisContext> GetAnalysisContextAsync(
        DateTime nowUtc,
        DateTime historyCutoffUtc,
        bool includeHistory,
        CancellationToken cancellationToken);
}
