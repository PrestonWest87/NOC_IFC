using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.AIOps;

namespace NocIfc.Api.Controllers.AIOps;

[ApiController]
[Route("api/v1")]
[RequirePage("AIOps RCA")]
public sealed class AiopsRcaReadController(
    AiopsDashboardQueries dashboard,
    AiopsRcaAnalysisQueries analysis,
    AiopsInvestigationState investigating) : ControllerBase
{
    [HttpGet("aiops/dashboard")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    public async Task<IActionResult> GetAiopsDashboard(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok(AiopsDashboardResponse.From(await dashboard.GetBoardAsync(user, cancellationToken)));
    }

    [HttpGet("aiops/sites")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    public async Task<IActionResult> GetAiopsSites(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok((await dashboard.GetSitesAsync(user, cancellationToken))
            .Select(AiopsSiteResponse.From).ToArray());
    }

    [HttpGet("rca/dashboard")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    public async Task<IActionResult> GetRcaDashboard(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok(RcaDashboardResponse.From(await dashboard.GetBoardAsync(user, cancellationToken)));
    }

    [HttpPost("rca/analyze")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Run RCA Analysis")]
    public async Task<IActionResult> Analyze(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok(AiopsRcaAnalysisResponse.From(await analysis.AnalyzeAsync(user, cancellationToken)));
    }

    [HttpPost("rca/investigate")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Dispatch RCA Tickets")]
    public async Task<IActionResult> SetInvestigating(
        [FromBody] JsonObject? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var site = request?["site"] is JsonValue siteValue && siteValue.TryGetValue<string>(out var name)
            ? name
            : "";
        if (site.Length == 0)
        {
            return UnprocessableEntity(new { detail = "site is required." });
        }
        if (request?["is_investigating"] is not JsonValue investigatingValue
            || !investigatingValue.TryGetValue<bool>(out var isInvestigating))
        {
            return UnprocessableEntity(new { detail = "is_investigating must be a boolean." });
        }
        if (!user.IsAdministrator)
        {
            var sites = await dashboard.GetSitesAsync(user, cancellationToken);
            if (!sites.Any(location => string.Equals(location.Name, site, StringComparison.Ordinal)))
            {
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    detail = new
                    {
                        code = "site_scope_denied",
                        message = "This site is outside your permitted site types.",
                    },
                });
            }
        }
        investigating.Set(site, isInvestigating);
        return Ok(new { status = "ok" });
    }
}
