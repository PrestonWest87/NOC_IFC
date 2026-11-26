using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
public sealed class AiSmtpSettingsController(AiSmtpSettingsCommands settings) : ControllerBase
{
    [HttpGet("/api/v1/settings/config")]
    [RequirePage("Settings & Admin")]
    [RequireAction("Tab: Settings -> AI & SMTP")]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var result = await settings.GetAsync(cancellationToken);
        return result is null ? Ok(new { }) : Ok(AiSmtpSettingsResponse.From(result));
    }

    [HttpPost("/api/v1/admin/config")]
    [RequireAdministrator]
    public async Task<IActionResult> Save(
        [FromBody] AiSmtpSettingsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await settings.SaveAsync(request.ToUpdate(), cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("/api/v1/admin/config/test-email")]
    [RequireAdministrator]
    public async Task<IActionResult> TestEmail(
        [FromBody] TestEmailRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await settings.SendTestEmailAsync(request.Recipient ?? "", cancellationToken);
            return result.Success
                ? Ok(new { status = "sent", message = result.Message })
                : StatusCode(StatusCodes.Status502BadGateway, new { detail = result.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
