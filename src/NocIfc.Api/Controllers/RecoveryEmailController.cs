using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public sealed class RecoveryEmailController(
    RecoveryEmailCommands recovery,
    UserAdminCommands userAdmin,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<RecoveryEmailController> logger) : ControllerBase
{
    [HttpGet("verify-recovery-email")]
    public async Task<IActionResult> Verify([FromQuery] string? token, CancellationToken cancellationToken)
    {
        if (!await recovery.VerifyAsync(token, cancellationToken))
        {
            return BadRequest(new
            {
                detail = new
                {
                    code = "invalid_email_verification",
                    message = "This verification link is invalid or expired.",
                },
            });
        }
        return Ok(new { status = "verified", message = "Your recovery email has been approved and verified." });
    }

    [HttpPost("request-recovery-email")]
    public async Task<IActionResult> RequestEmailChange([FromBody] RecoveryEmailRequest request, CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var submission = await recovery.SubmitAsync(user.Id, request.Email, cancellationToken);
            string message;
            if (submission.Notify.Count > 0)
            {
                QueueEmail(
                    string.Join(", ", submission.Notify),
                    "NOC Fusion Center recovery-email change request",
                    $"A recovery-email change request is awaiting review in Users & Roles. Request reference: {submission.RequestId}.");
                message = "Your recovery-email request was submitted. A user administrator must approve it before it can be used for account recovery.";
            }
            else if (user.IsAdministrator)
            {
                message = "Your request was recorded, but no other verified recovery-email reviewer is configured. For initial administrator setup, configure DEFAULT_ADMIN_EMAIL and restart the API/worker, or add another verified user administrator to review it.";
            }
            else
            {
                message = "Your request was recorded, but no verified recovery-email reviewer is configured. A user administrator must have a verified recovery email before this request can be approved.";
            }
            return Ok(new { status = "pending_approval", message });
        }
        catch (RecoveryEmailException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("resend-recovery-email-verification")]
    public async Task<IActionResult> Resend(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            var verification = await recovery.ResendAsync(user.Id, cancellationToken);
            var baseUrl = await PublicAppUrlAsync(cancellationToken);
            var verifyUrl = $"{baseUrl}/#/verify-email?token={Uri.EscapeDataString(verification.Token)}";
            QueueEmail(
                verification.Email,
                "Verify your NOC Fusion Center recovery email",
                $"Use this link to verify your recovery email address:\n\n{verifyUrl}");
            return Ok(new { status = "sent", message = "A new verification link was sent to the pending recovery email." });
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

    private void QueueEmail(string recipients, string subject, string body)
    {
        Response.OnCompleted(async () =>
        {
            try
            {
                var result = await emailSender.SendPlainTextAsync(recipients, subject, body, CancellationToken.None);
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
