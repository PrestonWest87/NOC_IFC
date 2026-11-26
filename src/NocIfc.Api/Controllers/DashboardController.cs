using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/dashboard")]
[RequirePage("Global Dashboards")]
public sealed class DashboardController(
    DashboardQueries dashboard,
    InternalRiskQueries internalRisk,
    ThreatArticleQueries articles) : ControllerBase
{
    [HttpGet("metrics")]
    [RequireAction("Tab: Dashboards -> Operational")]
    public async Task<IActionResult> GetMetrics(CancellationToken cancellationToken) =>
        Ok(DashboardMetricsResponse.From(await dashboard.GetMetricsAsync(cancellationToken)));

    [HttpGet("pinned-articles")]
    [RequireAction("Tab: Dashboards -> Operational")]
    public async Task<IActionResult> GetPinnedArticles(CancellationToken cancellationToken) =>
        Ok((await articles.GetPinnedAsync(cancellationToken)).Select(ThreatArticleResponse.From).ToArray());

    [HttpGet("live-articles")]
    [RequireAction("Tab: Dashboards -> Operational")]
    public async Task<IActionResult> GetLiveArticles(
        [FromQuery] int limit = 15,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await articles.GetLiveAsync(limit, cancellationToken);
            return Ok(result.Select(ThreatArticleResponse.From).ToArray());
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("hazards")]
    [RequireAction("Tab: Dashboards -> Operational")]
    public async Task<IActionResult> GetHazards(
        [FromQuery] int limit = 15,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await dashboard.GetHazardsAsync(limit, cancellationToken);
            return Ok(result.Select(DashboardRegionalHazardResponse.From).ToArray());
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("threat-trends")]
    [RequireAction("Tab: Dashboards -> Global Risk")]
    public async Task<IActionResult> GetThreatTrends(
        [FromQuery] int days = 14,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var scores = await dashboard.GetThreatTrendsAsync(days, cancellationToken);
            return Ok(scores.Select(DailyThreatScoreResponse.From).ToArray());
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("internal-risk")]
    [RequireAction("Tab: Dashboards -> Internal Risk")]
    public async Task<IActionResult> GetInternalRisk(CancellationToken cancellationToken)
    {
        var result = await internalRisk.GetLatestAsync(cancellationToken);
        return result is null
            ? Ok(new { status = "empty", message = "No internal risk snapshot available yet." })
            : Ok(InternalRiskResponse.From(result));
    }

    [HttpGet("internal-risk/history")]
    [RequireAction("Tab: Dashboards -> Internal Risk")]
    public async Task<IActionResult> GetInternalRiskHistory(
        [FromQuery] int days = 28,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await internalRisk.GetHistoryAsync(days, cancellationToken);
            return Ok(result.Select(InternalRiskHistoryResponse.From).ToArray());
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("briefs")]
    public async Task<IActionResult> GetBriefs(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok(await dashboard.GetBriefsAsync(user, cancellationToken));
    }

    [HttpPost("articles/toggle-pin")]
    [RequireAction("Tab: Dashboards -> Operational")]
    [RequireAction("Action: Pin Articles")]
    public async Task<IActionResult> TogglePin(
        [FromQuery(Name = "article_id")] int articleId,
        CancellationToken cancellationToken)
    {
        await articles.TogglePinAsync(articleId, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("articles/boost-score")]
    [RequireAction("Tab: Dashboards -> Operational")]
    [RequireAction("Action: Boost Threat Score")]
    public async Task<IActionResult> BoostScore(
        [FromQuery(Name = "article_id")] int articleId,
        [FromQuery] int amount = 15,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await articles.BoostScoreAsync(articleId, amount, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
