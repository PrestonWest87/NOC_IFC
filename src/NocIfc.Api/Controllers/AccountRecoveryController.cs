using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/user-admin/recovery-requests")]
[RequirePage("Settings & Admin")]
[RequireAction("Tab: Settings -> Users & Roles")]
public sealed class AccountRecoveryController(
    AccountRecoveryCommands recovery,
    UserAdminCommands userAdmin,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<AccountRecoveryController> logger) : ControllerBase
{
    [HttpGet]
    [RequireAction("Action: Review Account Recovery Requests")]
    public async Task<ActionResult<IReadOnlyList<PasswordResetRequestResponse>>> List(CancellationToken cancellationToken)
    {
        var requests = await recovery.ListPasswordResetRequestsAsync(cancellationToken);
        return Ok(requests.Select(PasswordResetRequestResponse.From).ToArray());
    }

    [HttpPost("{requestId:int}/decision")]
    [RequireAction("Action: Review Account Recovery Requests")]
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
            var result = await recovery.ReviewPasswordResetRequestAsync(
                requestId,
                reviewer.Id,
                request.Approve.Value,
                request.Reason,
                cancellationToken);
            if (result.Status == "approved")
            {
                var baseUrl = await RegistrationBaseUrlAsync(cancellationToken);
                var resetUrl = $"{baseUrl}/#/reset-password?token={Uri.EscapeDataString(result.Token!)}";
                QueueEmail(
                    result.Email!,
                    "NOC Fusion Center password reset",
                    $"Your password-reset request was approved. Use the following single-use link within 60 minutes:\n\n{resetUrl}");
                return Ok(new { status = "approved", username = result.Username });
            }

            if (result.Email is not null)
            {
                var denialReason = string.IsNullOrWhiteSpace(request.Reason)
                    ? "Contact a user administrator."
                    : request.Reason.Trim();
                QueueEmail(
                    result.Email,
                    "NOC Fusion Center recovery request update",
                    $"Your password-reset request was not approved. Reason: {denialReason}");
            }
            return Ok(new { status = "denied" });
        }
        catch (AccountRecoveryException exception)
        {
            return Conflict(new { detail = exception.Message });
        }
    }

    private async Task<string> RegistrationBaseUrlAsync(CancellationToken cancellationToken)
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
                    logger.LogError("Recovery notification delivery failed reason={Reason}", result.Message);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Recovery notification delivery raised unexpectedly.");
            }
        });
    }
}
