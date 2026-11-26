using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.AIOps;

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

    [HttpPost("rca/acknowledge")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Acknowledge RCA Alerts")]
    public async Task<IActionResult> Acknowledge(
        [FromBody] int[]? alertIds,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (!await dashboard.AcknowledgeAlertsAsync(user, alertIds ?? [], cancellationToken))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "One or more alerts are outside your permitted site types.",
                },
            });
        }
        return Ok(new { status = "ok" });
    }

    [HttpPost("rca/dispatch")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Dispatch RCA Tickets")]
    public async Task<IActionResult> Dispatch(
        [FromBody] RcaDispatchRequest? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var dispatch = request ?? new RcaDispatchRequest();
        if (!await dashboard.SetClusterDispatchAsync(
                user, dispatch.AlertIds, dispatch.IsDispatched, cancellationToken))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "One or more alerts are outside your permitted site types.",
                },
            });
        }
        return Ok(new { status = "ok" });
    }

    [HttpPost("rca/needs-dispatch")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Dispatch RCA Tickets")]
    public async Task<IActionResult> SetNeedsDispatch(
        [FromBody] JsonObject? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request?["needs_dispatch"] is not JsonValue dispatchValue
            || !dispatchValue.TryGetValue<bool>(out var needsDispatch))
        {
            return UnprocessableEntity(new { detail = "needs_dispatch must be a boolean." });
        }
        var site = request?["site"] is JsonValue siteValue && siteValue.TryGetValue<string>(out var siteName)
            ? siteName
            : "";

        var result = await dashboard.SetSiteNeedsDispatchAsync(
            user, site, needsDispatch, cancellationToken);
        return result.Outcome switch
        {
            AiopsNeedsDispatchOutcome.SiteScopeDenied => StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "This site is outside your permitted site types.",
                },
            }),
            AiopsNeedsDispatchOutcome.SiteNotFound => NotFound(new { detail = "Site not found." }),
            AiopsNeedsDispatchOutcome.ActiveAlertRequired => Conflict(new
            {
                detail = "Needs Dispatch requires at least one active site alert.",
            }),
            _ => Ok(new { status = "ok", updated_alerts = result.UpdatedAlerts }),
        };
    }

    [HttpPost("rca/site-maintenance")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Manage Site Maintenance")]
    public async Task<IActionResult> SetSiteMaintenance(
        [FromBody] JsonObject? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var siteName = request?["site_name"] is JsonValue siteValue
            && siteValue.TryGetValue<string>(out var site)
                ? site.Trim()
                : "";
        if (siteName.Length == 0)
        {
            return UnprocessableEntity(new { detail = "site_name is required." });
        }
        if (request?["is_maint"] is not JsonValue maintenanceValue
            || !maintenanceValue.TryGetValue<bool>(out var isMaintenance))
        {
            return UnprocessableEntity(new { detail = "is_maint must be a boolean." });
        }

        string? etr = null;
        if (isMaintenance && request?["etr"] is { } etrNode)
        {
            etr = etrNode is JsonValue etrValue && etrValue.TryGetValue<string>(out var etrText)
                ? etrText
                : "Invalid";
        }
        var reason = request?["reason"] is JsonValue reasonValue
            && reasonValue.TryGetValue<string>(out var reasonText)
                ? reasonText
                : null;
        var result = await dashboard.SetSiteMaintenanceAsync(
            user, siteName, isMaintenance, etr, reason, cancellationToken);
        return result switch
        {
            AiopsSiteMaintenanceOutcome.SiteScopeDenied => StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "This site is outside your permitted site types.",
                },
            }),
            AiopsSiteMaintenanceOutcome.InvalidEtr => UnprocessableEntity(new { detail = "etr must be an ISO date." }),
            AiopsSiteMaintenanceOutcome.SiteNotFound => NotFound(new { detail = "Site not found." }),
            _ => Ok(new { status = "ok" }),
        };
    }

    [HttpPost("rca/resolve-site")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Acknowledge RCA Alerts")]
    public async Task<IActionResult> ResolveSite(
        [FromBody] JsonObject? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var siteName = request?["site_name"] is JsonValue siteValue
            && siteValue.TryGetValue<string>(out var site)
                ? site.Trim()
                : "";
        if (siteName.Length == 0)
        {
            return UnprocessableEntity(new { detail = "site_name is required." });
        }
        var result = await dashboard.ResolveSiteAsync(user, siteName, cancellationToken);
        if (result.Outcome == AiopsSiteResolutionOutcome.SiteScopeDenied)
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
        if (result.Outcome == AiopsSiteResolutionOutcome.SiteNotFound)
        {
            return NotFound(new { detail = "Site not found." });
        }
        investigating.Set(siteName, false);
        return Ok(new { status = "ok", resolved_alerts = result.ResolvedAlerts });
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
