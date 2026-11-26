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
        var canViewChronicInsights = await HasAllSiteTypeAccessAsync(user, cancellationToken);

        var nowUtc = DateTime.UtcNow;
        var context = await analysisStore.GetAnalysisContextAsync(
            nowUtc, nowUtc.AddDays(-60), canViewChronicInsights, cancellationToken);
        return engine.Analyze(
            inputs.Alerts, inputs.Events, inputs.Locations, context, canViewChronicInsights, nowUtc);
    }

    public async Task<AiopsRcaAnalysisResult?> AnalyzeSitrepAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        if (!await HasAllSiteTypeAccessAsync(user, cancellationToken)) return null;
        var inputs = await dashboard.GetGlobalInputsAsync(user, cancellationToken);
        var nowUtc = DateTime.UtcNow;
        var context = await analysisStore.GetAnalysisContextAsync(
            nowUtc, nowUtc.AddDays(-60), false, cancellationToken);
        return engine.Analyze(
            inputs.Alerts, inputs.Events, inputs.Locations, context, false, nowUtc, includeFleetCorrelations: false);
    }

    private async Task<bool> HasAllSiteTypeAccessAsync(
        AuthenticatedUser user,
        CancellationToken cancellationToken)
    {
        if (user.IsAdministrator) return true;
        var allSiteTypes = await siteTypes.ExecuteAsync(cancellationToken);
        return new HashSet<string>(user.AllowedSiteTypes, StringComparer.Ordinal).IsSupersetOf(allSiteTypes);
    }
}
