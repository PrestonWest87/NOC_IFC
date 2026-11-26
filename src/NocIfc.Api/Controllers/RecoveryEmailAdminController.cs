using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/user-admin/email-change-requests")]
[RequirePage("Settings & Admin")]
[RequireAction("Tab: Settings -> Users & Roles")]
public sealed class RecoveryEmailAdminController(
    RecoveryEmailCommands recovery,
    UserAdminCommands userAdmin,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<RecoveryEmailAdminController> logger) : ControllerBase
{
    [HttpGet]
    [RequireAction("Action: Approve Recovery Email Changes")]
    public async Task<ActionResult<IReadOnlyList<RecoveryEmailRequestResponse>>> List(CancellationToken cancellationToken)
    {
        var requests = await recovery.ListPendingAsync(cancellationToken);
        return Ok(requests.Select(RecoveryEmailRequestResponse.From).ToArray());
    }

    [HttpPost("{requestId:int}/decision")]
    [RequireAction("Action: Approve Recovery Email Changes")]
    public async Task<IActionResult> Decide(
        int requestId,
        [FromBody] ReviewDecisionRequest request,
        CancellationToken cancellationToken)
    {
        var reviewer = AuthenticatedUserContext.GetUser(HttpContext);
        if (reviewer is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request.Approve is null || (request.Reason?.Length ?? 0) > 1000)
        {
            return BadRequest(new { detail = "A decision and a reason no longer than 1000 characters are required." });
        }

        try
        {
            var result = await recovery.ReviewAsync(
                requestId,
                reviewer.Id,
                request.Approve.Value,
                request.Reason,
                cancellationToken);
            if (result.Status == "pending_verification")
            {
                var baseUrl = await PublicAppUrlAsync(cancellationToken);
                var verifyUrl = $"{baseUrl}/#/verify-email?token={Uri.EscapeDataString(result.Token!)}";
                QueueEmail(
                    result.Email!,
                    "Verify your NOC Fusion Center recovery email",
                    $"Your recovery-email change was approved. Verify this email address using this link:\n\n{verifyUrl}");
            }
            else if (result.Email is not null)
            {
                var reason = string.IsNullOrWhiteSpace(request.Reason)
                    ? "Contact a user administrator."
                    : request.Reason.Trim();
                QueueEmail(
                    result.Email,
                    "NOC Fusion Center recovery-email request update",
                    $"Your recovery-email request was not approved. Reason: {reason}");
            }
            return Ok(new { status = result.Status, username = result.Username });
        }
        catch (RecoveryEmailException exception)
        {
            return Conflict(new { detail = exception.Message });
        }
    }

    private async Task<string> PublicAppUrlAsync(CancellationToken cancellationToken)
    {
        var stored = await userAdmin.GetPublicAppUrlAsync(cancellationToken);
        return (string.IsNullOrEmpty(stored) ? configuration["PUBLIC_APP_URL"] ?? "http://localhost:8503" : stored)
            .TrimEnd('/');
    }

    private void QueueEmail(string recipient, string subject, string body)
    {
        Response.OnCompleted(async () =>
        {
            try
            {
                var result = await emailSender.SendPlainTextAsync(recipient, subject, body, CancellationToken.None);
                if (!result.Success)
                {
                    logger.LogError("Recovery-email notification delivery failed reason={Reason}", result.Message);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Recovery-email notification delivery raised unexpectedly.");
            }
        });
    }
}
