using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NocIfc.Api.Authentication;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Authorization;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public abstract class RequirePermissionAttribute : Attribute, IAuthorizationFilter
{
    private readonly string _permission;
    private readonly string _scope;

    protected RequirePermissionAttribute(string permission, string scope)
    {
        var isKnown = scope == "page"
            ? PermissionCatalog.ContainsPage(permission)
            : PermissionCatalog.ContainsGrant(permission);
        if (!isKnown)
        {
            throw new ArgumentException($"Unknown {scope} permission: {permission}", nameof(permission));
        }

        _permission = permission;
        _scope = scope;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = AuthenticatedUserContext.GetUser(context.HttpContext);
        if (user is null)
        {
            context.Result = PermissionResponses.Unauthenticated();
            return;
        }

        var grants = _scope == "page" ? user.AllowedPages : user.AllowedActions;
        if (!user.IsAdministrator && !grants.Contains(_permission, StringComparer.Ordinal))
        {
            context.Result = PermissionResponses.Denied(_permission, _scope);
        }
    }
}

public sealed class RequirePageAttribute(string permission) : RequirePermissionAttribute(permission, "page")
{
}

public sealed class RequireActionAttribute(string permission) : RequirePermissionAttribute(permission, "action")
{
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class RequireAdministratorAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = AuthenticatedUserContext.GetUser(context.HttpContext);
        if (user is null)
        {
            context.Result = PermissionResponses.Unauthenticated();
        }
        else if (!user.IsAdministrator)
        {
            context.Result = PermissionResponses.Denied("Administrator", "role");
        }
    }
}

internal static class PermissionResponses
{
    public static ObjectResult Unauthenticated() => new(new
    {
        detail = new { code = "unauthenticated", message = "Not authenticated" },
    })
    {
        StatusCode = StatusCodes.Status401Unauthorized,
    };

    public static ObjectResult Denied(string permission, string scope)
    {
        var message = scope switch
        {
            "role" => "Administrator role required",
            "page" => $"Missing page permission: {permission}",
            _ => $"Missing permission: {permission}",
        };
        return new ObjectResult(new
        {
            detail = new
            {
                code = "permission_denied",
                scope,
                permission,
                message,
            },
        })
        {
            StatusCode = StatusCodes.Status403Forbidden,
        };
    }
}
