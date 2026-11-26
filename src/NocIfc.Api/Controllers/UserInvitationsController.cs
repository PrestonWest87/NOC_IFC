using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/user-admin/invitations")]
[RequirePage("Settings & Admin")]
[RequireAction("Tab: Settings -> Users & Roles")]
public sealed class UserInvitationsController(
    UserAdminCommands commands,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<UserInvitationsController> logger) : ControllerBase
{
    [HttpGet]
    [RequireAction("Action: Manage Users")]
    public async Task<ActionResult<IReadOnlyList<PendingInvitationResponse>>> List(CancellationToken cancellationToken)
    {
        var invitations = await commands.ListPendingInvitationsAsync(cancellationToken);
        return Ok(invitations.Select(PendingInvitationResponse.From).ToArray());
    }

    [HttpPost]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> Create(
        [FromBody] IndividualInviteRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var invite = await commands.CreateInvitationAsync(
                actor,
                request.Username,
                request.Email,
                request.Role,
                actor.Username,
                request.TtlHours,
                cancellationToken);
            var registrationUrl = await RegistrationUrlAsync(invite.Token, cancellationToken);
            var body = string.Join("\n", [
                "You have been invited to the NOC Fusion Center.",
                "",
                $"Username: {invite.Username}",
                $"Registration link: {registrationUrl}",
                "",
                $"This invitation expires at {invite.ExpiresAt.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", System.Globalization.CultureInfo.InvariantCulture)} UTC.",
            ]);
            QueueEmail(invite.Email, "NOC Fusion Center account invitation", body);
            return Ok(new InvitationDeliveryResponse(
                "invited", "queued", invite.Username, invite.Email, invite.Role, registrationUrl, invite.ExpiresAt));
        }
        catch (UserAdminCommandException exception)
        {
            return CommandFailure(exception);
        }
    }

    [HttpPost("{inviteId:int}/resend")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> Resend(int inviteId, CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var invite = await commands.ResendInvitationAsync(actor, inviteId, cancellationToken);
            var registrationUrl = await RegistrationUrlAsync(invite.Token, cancellationToken);
            var body = string.Join("\n", [
                "Your account invitation has been resent.",
                $"Registration link: {registrationUrl}",
                $"Expires: {invite.ExpiresAt.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", System.Globalization.CultureInfo.InvariantCulture)} UTC",
            ]);
            QueueEmail(invite.Email, "NOC Fusion Center account invitation", body);
            return Ok(new InvitationDeliveryResponse(
                "resent", null, null, null, null, registrationUrl, invite.ExpiresAt));
        }
        catch (UserAdminCommandException exception)
        {
            return CommandFailure(exception);
        }
    }

    [HttpDelete("{inviteId:int}")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> Revoke(int inviteId, CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return await commands.RevokeInvitationAsync(inviteId, actor.Id, cancellationToken)
            ? Ok(new { status = "revoked" })
            : NotFound(new { detail = "Pending invitation not found." });
    }

    private async Task<string> RegistrationUrlAsync(string token, CancellationToken cancellationToken)
    {
        var storedUrl = await commands.GetPublicAppUrlAsync(cancellationToken);
        var baseUrl = string.IsNullOrEmpty(storedUrl)
            ? configuration["PUBLIC_APP_URL"] ?? "http://localhost:8503"
            : storedUrl;
        return $"{baseUrl.TrimEnd('/')}/#/register?token={Uri.EscapeDataString(token)}";
    }

    private void QueueEmail(string recipient, string subject, string body)
    {
        Response.OnCompleted(async () =>
        {
            try
            {
                var result = await emailSender.SendPlainTextAsync(
                    recipient,
                    subject,
                    body,
                    CancellationToken.None);
                if (!result.Success)
                {
                    logger.LogError("Invitation email delivery failed reason={Reason}", result.Message);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Invitation email delivery raised unexpectedly.");
            }
        });
    }

    private IActionResult CommandFailure(UserAdminCommandException exception) =>
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
