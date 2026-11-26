namespace NocIfc.Application.Abstractions.Identity;

public interface ISiteTypeDirectory
{
    Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken);
}
