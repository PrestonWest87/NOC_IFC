using NocIfc.Application.Abstractions.AIOps;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.AIOps;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.AIOps;

public sealed class AiopsRcaAnalysisQueries(
    AiopsDashboardQueries dashboard,
    IAiopsRcaAnalysisStore analysisStore,
    SiteTypeQueries siteTypes,
    AiopsRcaAnalysisEngine engine)
{
    public async Task<AiopsRcaAnalysisResult> AnalyzeAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        var inputs = await dashboard.GetScopedInputsAsync(user, cancellationToken);
        var canViewChronicInsights = user.IsAdministrator;
        if (!canViewChronicInsights)
        {
            var allSiteTypes = await siteTypes.ExecuteAsync(cancellationToken);
            canViewChronicInsights = new HashSet<string>(user.AllowedSiteTypes, StringComparer.Ordinal)
                .IsSupersetOf(allSiteTypes);
        }

        var nowUtc = DateTime.UtcNow;
        var context = await analysisStore.GetAnalysisContextAsync(
            nowUtc, nowUtc.AddDays(-60), canViewChronicInsights, cancellationToken);
        return engine.Analyze(
            inputs.Alerts, inputs.Events, inputs.Locations, context, canViewChronicInsights, nowUtc);
    }
}
