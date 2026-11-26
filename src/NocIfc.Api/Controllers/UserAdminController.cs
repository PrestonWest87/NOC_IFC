using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/user-admin")]
[RequirePage("Settings & Admin")]
[RequireAction("Tab: Settings -> Users & Roles")]
public sealed class UserAdminController(
    RoleQueries roleQueries,
    SiteTypeQueries siteTypeQueries,
    UserDirectoryQueries userDirectoryQueries,
    RoleCommands roleCommands,
    UserAdminCommands userAdminCommands) : ControllerBase
{
    [HttpPost("display-accounts")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> CreateDisplayAccount(
        [FromBody] DisplayAccountRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var userId = await userAdminCommands.CreateDisplayAccountAsync(
                user,
                request.Username,
                request.Password,
                request.Role,
                request.FullName,
                cancellationToken);
            return Ok(new { status = "created", user_id = userId, account_type = "display" });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPut("users/{username}/role")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> ChangeUserRole(
        string username,
        [FromBody] RoleChangeRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request.Role is null || request.Role.Length is < 1 or > 64)
        {
            return BadRequest(new { detail = "Role name must contain 1-64 characters." });
        }

        try
        {
            return await userAdminCommands.ChangeRoleAsync(user, username, request.Role, cancellationToken)
                ? Ok(new { status = "updated" })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPatch("users/{username}/status")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> SetUserStatus(
        string username,
        [FromBody] UserStatusRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request.IsActive is null)
        {
            return BadRequest(new { detail = "is_active is required." });
        }

        try
        {
            return await userAdminCommands.SetActiveAsync(user, username, request.IsActive.Value, cancellationToken)
                ? Ok(new { status = "updated", is_active = request.IsActive.Value })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPost("users/{username}/revoke-sessions")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> RevokeUserSessions(string username, CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            return await userAdminCommands.RevokeSessionsAsync(user, username, cancellationToken)
                ? Ok(new { status = "revoked" })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPost("users/{username}/administrator-reset")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> AdministratorReset(
        string username,
        [FromBody] AdministratorResetRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            return await userAdminCommands.AdministratorResetAsync(
                user,
                username,
                request.NewPassword,
                cancellationToken)
                ? Ok(new { status = "reset", sessions_revoked = true })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPut("users/{username}/profile")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> UpdateUserIdentity(
        string username,
        [FromBody] UserIdentityRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            return await userAdminCommands.UpdateIdentityAsync(
                user,
                username,
                request.FullName,
                request.JobTitle,
                request.ContactInfo,
                cancellationToken)
                ? Ok(new { status = "updated" })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpPatch("users/{username}/account-type")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> SetAccountType(
        string username,
        [FromBody] AccountTypeRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var accountType = await userAdminCommands.SetAccountTypeAsync(
                user,
                username,
                request.AccountType,
                cancellationToken);
            return accountType is null
                ? NotFound(new { detail = "User not found." })
                : Ok(new { status = "updated", account_type = accountType });
        }
        catch (UserAdminCommandException exception)
        {
            return UserAdminCommandFailure(exception);
        }
    }

    [HttpGet("users")]
    [RequireAction("Action: Manage Users")]
    public async Task<ActionResult<IReadOnlyList<UserDirectoryResponse>>> ListUsers(
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        var users = await userDirectoryQueries.ExecuteAsync(cancellationToken);
        return Ok(users.Select(UserDirectoryResponse.From).ToArray());
    }

    [HttpGet("roles")]
    [RequireAction("Action: Manage Users")]
    public async Task<ActionResult<IReadOnlyList<RoleResponse>>> ListAssignableRoles(
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        var roles = await roleQueries.ListAssignableRolesAsync(user, cancellationToken);
        return Ok(roles.Select(RoleResponse.From).ToArray());
    }

    [HttpGet("role-definitions")]
    [RequireAction("Action: Manage Roles")]
    public async Task<ActionResult<IReadOnlyList<RoleResponse>>> ListRoleDefinitions(
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        var roles = await roleQueries.ListRoleDefinitionsAsync(user, cancellationToken);
        return Ok(roles.Select(RoleResponse.From).ToArray());
    }

    [HttpGet("site-types")]
    [RequireAction("Action: Manage Roles")]
    public async Task<ActionResult<IReadOnlyList<string>>> ListSiteTypes(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        return Ok(await siteTypeQueries.ExecuteAsync(cancellationToken));
    }

    [HttpPost("roles")]
    [RequireAction("Action: Manage Roles")]
    public async Task<IActionResult> CreateRole(
        [FromBody] RoleDefinitionRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var created = await roleCommands.CreateAsync(user, request.ToInput(), cancellationToken);
            return created
                ? Ok(new { status = "created" })
                : Conflict(new { detail = "Role already exists." });
        }
        catch (RoleCommandException exception)
        {
            return RoleCommandFailure(exception);
        }
    }

    [HttpPut("roles/{name}")]
    [RequireAction("Action: Manage Roles")]
    public async Task<IActionResult> UpdateRole(
        string name,
        [FromBody] RoleDefinitionRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var updated = await roleCommands.UpdateAsync(user, name, request.ToInput(), cancellationToken);
            return updated
                ? Ok(new { status = "updated" })
                : NotFound(new { detail = "Role not found." });
        }
        catch (RoleCommandException exception)
        {
            return RoleCommandFailure(exception);
        }
    }

    private IActionResult RoleCommandFailure(RoleCommandException exception) => exception.PermissionDenied
        ? StatusCode(exception.StatusCode, new
        {
            detail = new
            {
                code = "permission_denied",
                permission = "Action: Manage Roles",
                message = exception.Message,
            },
        })
        : StatusCode(exception.StatusCode, new { detail = exception.Message });

    private IActionResult UserAdminCommandFailure(UserAdminCommandException exception) =>
        exception.StatusCode == StatusCodes.Status403Forbidden
            ? StatusCode(exception.StatusCode, new
            {
                detail = new
                {
                    code = "permission_denied",
                    scope = exception.Scope,
                    permission = exception.Permission,
                    message = exception.Message,
                },
            })
            : StatusCode(exception.StatusCode, new { detail = exception.Message });
}
