using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using NocIfc.Api.Authorization;
using NocIfc.Api.Controllers;
using NocIfc.Api.Controllers.AIOps;
using Xunit;

namespace NocIfc.Api.Tests;

public sealed class LegacyApiCompatibilityTests
{
    [Theory]
    [InlineData(typeof(LegacySettingsCompatibilityController), nameof(LegacySettingsCompatibilityController.GetUsers), "GET", "api/v1/settings/users")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.GetLists), "GET", "api/v1/admin/lists")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.GetRoles), "GET", "api/v1/admin/roles")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.CreateRole), "POST", "api/v1/admin/roles")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.UpdateRole), "PUT", "api/v1/admin/roles/{name}")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.CreateDisplayAccount), "POST", "api/v1/admin/users")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.CreateInvitation), "POST", "api/v1/admin/registration-invites")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.ChangeUserRole), "PUT", "api/v1/admin/users/{username}/role")]
    [InlineData(typeof(LegacyAdminCompatibilityController), nameof(LegacyAdminCompatibilityController.ResetPassword), "POST", "api/v1/admin/users/{username}/reset-password")]
    [InlineData(typeof(AiopsRcaReadController), nameof(AiopsRcaReadController.GetSitrep), "GET", "api/v1/aiops/sitrep")]
    [InlineData(typeof(AiopsRcaReadController), nameof(AiopsRcaReadController.AcknowledgeAiopsSite), "PATCH", "api/v1/aiops/sites/{siteId:int}/acknowledge")]
    public void RegistersLegacyPathAndMethod(Type controllerType, string actionName, string method, string path)
    {
        var action = controllerType.GetMethod(actionName)!;
        var prefix = controllerType.GetCustomAttribute<RouteAttribute>()!.Template!;
        var matches = action.GetCustomAttributes<HttpMethodAttribute>().Any(route =>
            route.HttpMethods.Contains(method, StringComparer.Ordinal)
            && string.Equals(
                string.Join('/', prefix.Trim('/'), (route.Template ?? "").Trim('/')),
                path,
                StringComparison.Ordinal));

        Assert.True(matches, $"Expected {method} {path} on {controllerType.Name}.{actionName}.");
    }

    [Fact]
    public void LegacyAdminAliasesRetainAdministratorOnlyAuthorization()
    {
        Assert.NotNull(typeof(LegacyAdminCompatibilityController)
            .GetCustomAttribute<RequireAdministratorAttribute>());
        Assert.Null(typeof(LegacySettingsCompatibilityController)
            .GetCustomAttribute<RequirePageAttribute>());
        var userDirectoryActions = typeof(LegacySettingsCompatibilityController)
            .GetMethod(nameof(LegacySettingsCompatibilityController.GetUsers))!
            .GetCustomAttributes<RequireActionAttribute>()
            .ToArray();
        Assert.Equal(2, userDirectoryActions.Length);
    }
}
