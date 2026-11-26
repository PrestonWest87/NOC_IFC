using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/application-settings")]
[RequirePage("Settings & Admin")]
[RequireAction("Tab: Settings -> Application Settings")]
public sealed class ApplicationSettingsController(
    ApplicationSettingsCommands settings,
    RiskScoringCommands riskScoring,
    OperationalIntegrationSettingsCommands integrations,
    SchedulerSettingsCommands scheduler) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }

        var result = await settings.GetAsync(user, cancellationToken);
        return result is null
            ? Ok(new { public_app_url = "", tech_stack = "", monitored_asns = "" })
            : Ok(ApplicationSettingsResponse.From(result));
    }

    [HttpPut]
    [RequireAction("Action: Manage Application Settings")]
    public async Task<IActionResult> Update(
        [FromBody] ApplicationSettingsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await settings.SaveAsync(request.ToUpdate(), cancellationToken);
            return Ok(new { status = "updated" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("risk-scoring")]
    public async Task<IActionResult> GetRiskScoring(CancellationToken cancellationToken)
    {
        var result = await riskScoring.GetAsync(cancellationToken);
        return result is null ? Ok(new { }) : Ok(RiskScoringSettingsResponse.From(result));
    }

    [HttpPut("risk-scoring")]
    [RequireAction("Action: Adjust Risk Scoring Overrides")]
    public async Task<IActionResult> UpdateRiskScoring(
        [FromBody] RiskScoringSettingsRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            await riskScoring.UpdateAsync(request.ToSettings(), cancellationToken);
            return Ok(new { status = "updated" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("integrations")]
    [RequireAction("Action: Manage Application Settings")]
    public async Task<IActionResult> GetIntegrations(CancellationToken cancellationToken)
    {
        var result = await integrations.GetAsync(cancellationToken);
        return Ok(IntegrationSettingsResponse.From(result));
    }

    [HttpPut("integrations")]
    [RequireAction("Action: Manage Application Settings")]
    public async Task<IActionResult> UpdateIntegrations(
        [FromBody] IntegrationSettingsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            await integrations.SaveAsync(request.ToUpdate(), user.Id, cancellationToken);
            return Ok(new { status = "updated" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("scheduler")]
    public async Task<IActionResult> GetScheduler(CancellationToken cancellationToken) =>
        Ok(SchedulerSettingsResponse.From(await scheduler.GetAsync(cancellationToken)));

    [HttpPatch("scheduler/jobs/{jobKey}")]
    [RequireAction("Action: Manage Scheduler Settings")]
    public async Task<IActionResult> UpdateSchedulerJob(
        string jobKey,
        [FromBody] SchedulerUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var result = await scheduler.SaveAsync(
                jobKey,
                request.ToUpdate(),
                user.Username,
                user.Id,
                cancellationToken);
            return Ok(SchedulerUpdateResponse.From(result));
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }
}
