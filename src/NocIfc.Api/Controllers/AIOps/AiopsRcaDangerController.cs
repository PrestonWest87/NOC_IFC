using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers.AIOps;

[ApiController]
[Route("api/v1/rca")]
[RequirePage("AIOps RCA")]
public sealed class AiopsRcaDangerController(DangerZoneCommands dangerZone) : ControllerBase
{
    [HttpPost("clear-events")]
    [RequireAction("Tab: Settings -> Danger Zone")]
    [RequireAction("Action: Clear AIOps Data")]
    public async Task<IActionResult> ClearTimelineEvents(CancellationToken cancellationToken)
    {
        await dangerZone.ClearTimelineEventsAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("nuke-alerts")]
    [RequireAction("Tab: Settings -> Danger Zone")]
    [RequireAction("Action: Clear AIOps Data")]
    public async Task<IActionResult> ClearAlerts(CancellationToken cancellationToken)
    {
        await dangerZone.ClearActiveAlertsAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }
}
