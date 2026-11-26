using NocIfc.Application.Features.Identity;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class PermissionCatalogTests
{
    [Fact]
    public void SharedCatalogContainsCurrentRoleEditorKeysWithoutRetiredModelPermissions()
    {
        var catalog = PermissionCatalog.Value;
        var actions = catalog.GetProperty("actions").EnumerateArray()
            .Select(item => item.GetProperty("key").GetString())
            .ToArray();
        var settingsTabs = catalog.GetProperty("tabs").GetProperty("settings").EnumerateArray()
            .Select(item => item.GetProperty("key").GetString())
            .ToArray();

        Assert.Contains("Action: Manage Users", actions);
        Assert.Contains("Action: Manage Roles", actions);
        Assert.DoesNotContain("Action: Train ML Model", actions);
        Assert.DoesNotContain("Tab: Settings -> ML Training", settingsTabs);
    }
}
