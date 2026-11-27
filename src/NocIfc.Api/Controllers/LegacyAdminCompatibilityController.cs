using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/admin")]
[RequireAdministrator]
public sealed class LegacyAdminCompatibilityController(
    RssSettingsCommands rssSettings,
    UserDirectoryQueries users,
    RoleQueries roles,
    RoleCommands roleCommands,
    UserAdminCommands userAdmin,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<LegacyAdminCompatibilityController> logger) : ControllerBase
{
    [HttpGet("lists")]
    public async Task<IActionResult> GetLists(CancellationToken cancellationToken)
    {
        var catalog = await rssSettings.GetAsync(cancellationToken);
        var userRows = (await users.ExecuteAsync(cancellationToken)).Select(user =>
            (IReadOnlyDictionary<string, object?>)new Dictionary<string, object?>
            {
                ["id"] = user.Id,
                ["username"] = user.Username,
                ["role"] = user.Role,
                ["full_name"] = user.FullName,
            }).ToArray();
        return Ok(new
        {
            keywords = catalog.Keywords.Select(KeywordDirectoryResponse.From).ToArray(),
            feeds = catalog.Feeds.Select(FeedSourceResponse.From).ToArray(),
            users = userRows,
        });
    }

    [HttpGet("roles")]
    public async Task<IActionResult> GetRoles(CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        var definitions = await roles.ListRoleDefinitionsAsync(actor, cancellationToken);
        return Ok(definitions.Select(RoleResponse.From).ToArray());
    }

    [HttpPost("roles")]
    public async Task<IActionResult> CreateRole(
        [FromBody] RoleDefinitionRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        try
        {
            return await roleCommands.CreateAsync(actor, request.ToInput(), cancellationToken)
                ? Ok(new { status = "ok" })
                : Conflict(new { detail = "Role already exists." });
        }
        catch (RoleCommandException exception)
        {
            return RoleFailure(exception);
        }
    }

    [HttpPut("roles/{name}")]
    public async Task<IActionResult> UpdateRole(
        string name,
        [FromBody] RoleDefinitionRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        var input = request.ToInput() with { Name = name };
        try
        {
            return await roleCommands.UpdateAsync(actor, name, input, cancellationToken)
                ? Ok(new { status = "ok" })
                : NotFound(new { detail = "Role not found." });
        }
        catch (RoleCommandException exception)
        {
            return RoleFailure(exception);
        }
    }

    [HttpPost("users")]
    public async Task<IActionResult> CreateDisplayAccount(
        [FromBody] DisplayAccountRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        try
        {
            var id = await userAdmin.CreateDisplayAccountAsync(
                actor, request.Username, request.Password, request.Role ?? "viewer", request.FullName, cancellationToken);
            return Ok(new { status = "ok", user_id = id, account_type = "display" });
        }
        catch (UserAdminCommandException exception)
        {
            return UserFailure(exception);
        }
    }

    [HttpPost("registration-invites")]
    public async Task<IActionResult> CreateInvitation(
        [FromBody] LegacyRegistrationInviteRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        try
        {
            var ttlHours = request.TtlHours ?? DefaultInviteTtlHours();
            var invite = await userAdmin.CreateInvitationAsync(
                actor, request.Username, request.Email, request.Role ?? "analyst", actor.Username,
                ttlHours, cancellationToken);
            var baseUrl = await userAdmin.GetPublicAppUrlAsync(cancellationToken)
                ?? configuration["PUBLIC_APP_URL"]
                ?? "http://localhost:8501";
            var registrationUrl = $"{baseUrl.TrimEnd('/')}/#/register?token={Uri.EscapeDataString(invite.Token)}";
            var body = string.Join("\n", [
                "You have been invited to the NOC Fusion Center.",
                $"Username: {invite.Username}",
                $"Role: {invite.Role}",
                $"Registration link: {registrationUrl}",
                $"Expires: {invite.ExpiresAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture)} UTC",
            ]);
            QueueEmail(invite.Email, "NOC Fusion Center account invitation", body);
            return Ok(new LegacyRegistrationInviteResponse(
                invite.Username, invite.Email, invite.Role, invite.ExpiresAt, registrationUrl));
        }
        catch (UserAdminCommandException exception)
        {
            return UserFailure(exception);
        }
    }

    [HttpPut("users/{username}/role")]
    public async Task<IActionResult> ChangeUserRole(
        string username,
        [FromBody] RoleChangeRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        try
        {
            return await userAdmin.ChangeRoleAsync(actor, username, request.Role ?? "", cancellationToken)
                ? Ok(new { status = "ok" })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserFailure(exception);
        }
    }

    [HttpPost("users/{username}/reset-password")]
    public async Task<IActionResult> ResetPassword(
        string username,
        [FromBody] AdministratorResetRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null) return Unauthorized();
        try
        {
            return await userAdmin.AdministratorResetAsync(actor, username, request.NewPassword, cancellationToken)
                ? Ok(new { status = "ok" })
                : NotFound(new { detail = "User not found." });
        }
        catch (UserAdminCommandException exception)
        {
            return UserFailure(exception);
        }
    }

    private int DefaultInviteTtlHours()
    {
        var configured = configuration["REGISTRATION_INVITE_TTL_HOURS"];
        if (string.IsNullOrWhiteSpace(configured)) return 72;
        return int.TryParse(configured, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var ttlHours)
            ? ttlHours
            : throw new InvalidOperationException("REGISTRATION_INVITE_TTL_HOURS must be an integer.");
    }

    private void QueueEmail(string recipient, string subject, string body)
    {
        Response.OnCompleted(async () =>
        {
            try
            {
                var result = await emailSender.SendPlainTextAsync(recipient, subject, body, CancellationToken.None);
                if (!result.Success) logger.LogError("Legacy invitation delivery failed reason={Reason}", result.Message);
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Legacy invitation delivery raised unexpectedly.");
            }
        });
    }

    private IActionResult RoleFailure(RoleCommandException exception) =>
        StatusCode(exception.StatusCode, new { detail = exception.Message });

    private IActionResult UserFailure(UserAdminCommandException exception) =>
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

public sealed class LegacyRegistrationInviteRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("role")]
    public string? Role { get; init; }

    [JsonPropertyName("ttl_hours")]
    public int? TtlHours { get; init; }
}

public sealed record LegacyRegistrationInviteResponse(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("expires_at")] DateTime ExpiresAt,
    [property: JsonPropertyName("registration_url")] string RegistrationUrl);
