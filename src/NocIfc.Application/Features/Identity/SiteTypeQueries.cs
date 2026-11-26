using NocIfc.Application.Abstractions.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class SiteTypeQueries(ISiteTypeDirectory siteTypes)
{
    private static readonly string[] DefaultSiteTypes =
    ["NOC", "SOC", "Data Center", "Field Office", "HQ", "Remote Site", "Cloud"];

    public async Task<IReadOnlyList<string>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var databaseTypes = await siteTypes.GetDatabaseSiteTypesAsync(cancellationToken);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return DefaultSiteTypes.Concat(databaseTypes)
            .Where(type => !string.IsNullOrEmpty(type) && seen.Add(type))
            .ToArray();
    }
}
