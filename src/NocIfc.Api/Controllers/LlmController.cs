using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Regional;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/llm")]
public sealed class LlmController(
    LlmConnectionTestCommands connections,
    ExecutiveWeatherBriefCommands weatherBriefs) : ControllerBase
{
    [HttpPost("test-connection")]
    [RequirePage("Settings & Admin")]
    [RequireAction("Tab: Settings -> AI & SMTP")]
    [RequireAdministrator]
    public async Task<IActionResult> TestConnection(
        [FromBody] LlmConnectionTestRequest request,
        CancellationToken cancellationToken) =>
        Ok(await connections.TestAsync(request.ToInput(), cancellationToken));

    [HttpPost("executive-weather-brief")]
    [RequirePage("Regional Grid")]
    [RequireAction("Tab: Regional Grid -> Executive Dash")]
    [RequireAction("Action: Generate Reports")]
    public async Task<IActionResult> ExecutiveWeatherBrief(
        [FromBody] ExecutiveWeatherBriefRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A weather brief request is required." });
        }
        try
        {
            var brief = await weatherBriefs.GenerateAsync(request.Analytics, request.P1AtRisk, cancellationToken);
            return Ok(new { brief = string.IsNullOrEmpty(brief) ? "Unable to generate weather brief." : brief });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
