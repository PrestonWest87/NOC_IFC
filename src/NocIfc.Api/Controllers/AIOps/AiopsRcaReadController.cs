using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Api.Services;
using NocIfc.Application.Features.AIOps;
using NocIfc.Domain.AIOps;

namespace NocIfc.Api.Controllers.AIOps;

[ApiController]
[Route("api/v1")]
[RequirePage("AIOps RCA")]
public sealed class AiopsRcaReadController(
    AiopsDashboardQueries dashboard,
    AiopsRcaAnalysisQueries analysis,
    AiopsTicketCommands tickets,
    AiopsSitrepQueries sitrep,
    AiopsSitrepActionCommands sitrepActions,
    AiopsInvestigationState investigating,
    AiopsWebSocketHub websockets) : ControllerBase
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
        await websockets.BroadcastRefreshAsync(cancellationToken);
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
        await websockets.BroadcastRefreshAsync(cancellationToken);
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
        if (result.Outcome is AiopsNeedsDispatchOutcome.SiteScopeDenied)
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
        if (result.Outcome == AiopsNeedsDispatchOutcome.SiteNotFound)
        {
            return NotFound(new { detail = "Site not found." });
        }
        if (result.Outcome == AiopsNeedsDispatchOutcome.ActiveAlertRequired)
        {
            return Conflict(new { detail = "Needs Dispatch requires at least one active site alert." });
        }
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new { status = "ok", updated_alerts = result.UpdatedAlerts });
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
        if (result == AiopsSiteMaintenanceOutcome.SiteScopeDenied)
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
        if (result == AiopsSiteMaintenanceOutcome.InvalidEtr)
        {
            return UnprocessableEntity(new { detail = "etr must be an ISO date." });
        }
        if (result == AiopsSiteMaintenanceOutcome.SiteNotFound)
        {
            return NotFound(new { detail = "Site not found." });
        }
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new { status = "ok" });
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
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new { status = "ok", resolved_alerts = result.ResolvedAlerts });
    }

    [HttpPost("rca/resolve-alert")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Acknowledge RCA Alerts")]
    public async Task<IActionResult> ResolveAlert(
        [FromQuery(Name = "alert_id")] int alertId = 0,
        [FromQuery(Name = "node_name")] string? nodeName = "",
        CancellationToken cancellationToken = default)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (!await dashboard.ResolveAlertAsync(user, alertId, nodeName ?? "", cancellationToken))
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
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("rca/send-ticket")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Dispatch RCA Tickets")]
    public async Task<IActionResult> SendTicket(
        [FromBody] RcaSendTicketRequest? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A ticket request is required." });
        }
        if (request.AlertIds is null)
        {
            return UnprocessableEntity(new { detail = "alert_ids must be a list of integers." });
        }
        var result = await tickets.SendAsync(user, new AiopsManualTicket(
            request.Site, request.Priority, request.TicketText, request.Recipient,
            request.AlertIds, request.Sla), cancellationToken);
        if (result.ScopeFailure != AiopsTicketScopeFailure.None)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = result.ScopeFailure == AiopsTicketScopeFailure.Site
                        ? "This site is outside your permitted site types."
                        : "One or more alerts are outside your permitted site types.",
                },
            });
        }
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new
        {
            status = result.Delivery!.Success ? "ok" : "error",
            message = result.Delivery.Message,
        });
    }

    [HttpPost("rca/generate-ticket")]
    [RequireAction("Tab: AIOps RCA -> Active Board")]
    [RequireAction("Action: Dispatch RCA Tickets")]
    public async Task<IActionResult> GenerateTicket(
        [FromBody] RcaGenerateTicketRequest? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A ticket request is required." });
        }
        var site = request.Site ?? "";
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
        return Ok(new { ticket = AiopsRcaTicketTextGenerator.Generate(request.ToInput()) });
    }

    [HttpGet("rca/sitrep")]
    [RequireAction("Tab: AIOps RCA -> Global Correlation")]
    [RequireAction("Action: Generate Reports")]
    public async Task<IActionResult> GetSitrep(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var report = await sitrep.GenerateAsync(user, cancellationToken);
        if (report is null)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "This global sitrep requires access to all site types.",
                },
            });
        }
        return Ok(new { report });
    }

    [HttpPost("rca/sitrep")]
    [RequireAction("Tab: AIOps RCA -> Global Correlation")]
    public async Task<IActionResult> RunSitrepAction(
        [FromBody] RcaSitrepActionRequest? request,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var action = request?.Action ?? "";
        var permission = AiopsSitrepActionCommands.RequiredPermission(action);
        if (permission is null)
        {
            return Ok(new { status = "error", message = $"Unknown action: {action}" });
        }
        if (!user.IsAdministrator && !user.AllowedActions.Contains(permission, StringComparer.Ordinal))
        {
            return PermissionResponses.Denied(permission, "action");
        }
        if (action != "refresh_briefing"
            && !await analysis.HasAllSiteTypeAccessAsync(user, cancellationToken))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "site_scope_denied",
                    message = "This operation requires access to all site types.",
                },
            });
        }

        if (action == "refresh_briefing")
        {
            var result = await sitrepActions.RefreshBriefingAsync(cancellationToken);
            return result.Success
                ? Ok(new { status = "ok", summary = result.Content })
                : Ok(new { status = "error", message = result.Content });
        }
        if (action == "scoring_rationale")
        {
            var result = await sitrepActions.GenerateScoringRationaleAsync(
                request?.ToIntelInput() ?? new AiopsScoringRationaleInput("UNKNOWN", [], [], []),
                cancellationToken);
            return result.Success
                ? Ok(new { status = "ok", report = result.Content })
                : Ok(new { status = "error", message = result.Content });
        }
        return Ok(new { status = "ok", report = await sitrepActions.GenerateSecurityAuditAsync(cancellationToken) });
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
        await websockets.BroadcastRefreshAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }
}
