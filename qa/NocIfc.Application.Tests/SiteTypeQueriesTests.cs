using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using Xunit;

namespace NocIfc.Application.Tests;

public sealed class SiteTypeQueriesTests
{
    [Fact]
    public async Task MergesDefaultsAndDatabaseTypesInOrderWithoutDuplicates()
    {
        var queries = new SiteTypeQueries(new StubSiteTypeDirectory(["Custom", "NOC", "custom", ""]));

        var result = await queries.ExecuteAsync(CancellationToken.None);

        Assert.Equal(
            new[] { "NOC", "SOC", "Data Center", "Field Office", "HQ", "Remote Site", "Cloud", "Custom", "custom" },
            result);
    }

    private sealed class StubSiteTypeDirectory(IReadOnlyList<string> siteTypes) : ISiteTypeDirectory
    {
        public Task<IReadOnlyList<string>> GetDatabaseSiteTypesAsync(CancellationToken cancellationToken) =>
            Task.FromResult(siteTypes);
    }
}
