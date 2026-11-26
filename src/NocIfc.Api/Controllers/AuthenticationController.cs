using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.Email;
using NocIfc.Application.Abstractions.Identity;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
public sealed class AuthenticationController(
    AuthenticationService authentication,
    AccountRecoveryCommands accountRecovery,
    IFailedLoginAlertStore failedLoginAlerts,
    IEmailSender emailSender,
    ILogger<AuthenticationController> logger) : ControllerBase
{
    [HttpGet("register/validate")]
    public async Task<IActionResult> ValidateRegistration(
        [FromQuery] string? token,
        CancellationToken cancellationToken)
    {
        var invite = await authentication.GetRegistrationInviteAsync(token, cancellationToken);
        return invite is null
            ? BadRequest(new { detail = "This registration link is invalid, expired, or already used." })
            : Ok(RegistrationInviteResponse.From(invite));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(
        [FromBody] RegistrationRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await authentication.CompleteRegistrationAsync(request.ToInput(), cancellationToken);
            return Ok(new LoginResponse(LoginUserResponse.From(result.User), result.Token));
        }
        catch (RegistrationException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        var profile = await authentication.GetCurrentUserAsync(user.Id, cancellationToken);
        return profile is null
            ? Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } })
            : Ok(LoginUserResponse.From(profile));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request, CancellationToken cancellationToken)
    {
        if (request.Username is null || request.Password is null)
        {
            return BadRequest(new { detail = "username and password are required." });
        }

        var result = await authentication.AuthenticateAsync(request.Username, request.Password, cancellationToken);
        if (result is not null)
        {
            return Ok(new LoginResponse(LoginUserResponse.From(result.User), result.Token));
        }

        logger.LogWarning("POST /login failed.");
        try
        {
            var sourceIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var alert = await failedLoginAlerts.RecordAsync(request.Username, sourceIp, cancellationToken);
            if (alert is not null)
            {
                QueueAlert(alert);
            }
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Unable to record failed-login alert evidence.");
        }

        return Unauthorized(new { detail = new { code = "invalid_credentials", message = "Invalid credentials" } });
    }

    [HttpPost("request-password-reset")]
    public async Task<IActionResult> RequestPasswordReset(
        [FromBody] PasswordResetRequestBody request,
        CancellationToken cancellationToken)
    {
        var result = await accountRecovery.SubmitPasswordResetRequestAsync(
            request.Identifier,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
        if (result.Notify.Count > 0)
        {
            QueueEmail(
                string.Join(", ", result.Notify),
                "NOC Fusion Center password-reset request",
                $"A password-reset request is awaiting review in Users & Roles. Request reference: {result.RequestId}. Sign in to approve or deny it.");
        }
        return Ok(new
        {
            status = "accepted",
            message = "If this account can use recovery, its request has been submitted for administrator review. Accounts without an approved recovery email require administrator-assisted recovery.",
        });
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> CompletePasswordReset(
        [FromBody] PasswordResetCompletionRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            if (await accountRecovery.CompletePasswordResetAsync(request.Token, request.NewPassword, cancellationToken))
            {
                return Ok(new { status = "ok", message = "Password reset successfully. Sign in with your new password." });
            }
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
        return BadRequest(new
        {
            detail = new
            {
                code = "invalid_reset_token",
                message = "This password-reset link is invalid or expired.",
            },
        });
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        var token = AuthenticatedUserContext.GetToken(HttpContext);
        if (user is null || string.IsNullOrEmpty(token))
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        await authentication.RevokeSessionAsync(user.Id, token, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("update-profile")]
    public async Task<IActionResult> UpdateProfile(
        [FromBody] ProfileUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            await authentication.UpdateProfileAsync(
                user.Id,
                request.FullName,
                request.JobTitle,
                request.ContactInfo,
                request.DefaultShift,
                request.OldPassword,
                request.NewPassword,
                cancellationToken);
            return Ok(new { status = "ok", message = "Updated!" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("update-theme")]
    public async Task<IActionResult> UpdateTheme([FromBody] ThemeRequest request, CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        try
        {
            await authentication.UpdateThemeAsync(user.Id, request.Theme ?? "", cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    private void QueueAlert(FailedLoginAlert alert)
    {
        var (subject, body) = FailedLoginAlertText.Format(alert);
        Response.OnCompleted(async () =>
        {
            try
            {
                var result = await emailSender.SendPlainTextAsync(
                    alert.Recipients,
                    subject,
                    body,
                    CancellationToken.None);
                if (!result.Success)
                {
                    logger.LogError(
                        "Failed-login alert email delivery failed attempts={AttemptCount} reason={Reason}",
                        alert.Attempts.Count,
                        result.Message);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Failed-login alert delivery raised unexpectedly.");
            }
        });
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
                    logger.LogError("Account-recovery notification delivery failed reason={Reason}", result.Message);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Account-recovery notification delivery raised unexpectedly.");
            }
        });
    }
}
