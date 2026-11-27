using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.AIOps;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Threat;
using NocIfc.Api.Services;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/dashboard")]
[RequirePage("Global Dashboards")]
public sealed class DashboardController(
    DashboardQueries dashboard,
    ExecutiveIntelQueries executiveIntel,
    InternalRiskQueries internalRisk,
    ThreatArticleQueries articles,
    GenerateArticleBlufCommands blufCommands,
    AiopsSitrepActionCommands sitrepActions,
    UnifiedBriefGenerationState unifiedBriefGeneration) : ControllerBase
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

    [HttpGet("executive-intel")]
    [RequireAction("Tab: Dashboards -> Global Risk")]
    public async Task<IActionResult> GetExecutiveIntel(CancellationToken cancellationToken) =>
        Ok(ExecutiveIntelResponse.From(await executiveIntel.GetAsync(cancellationToken)));

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

    [HttpPost("generate-unified-brief")]
    [RequireAction("Tab: Dashboards -> Unified Brief")]
    [RequireAction("Action: Generate Reports")]
    public IActionResult GenerateUnifiedBrief()
    {
        var id = unifiedBriefGeneration.Start();
        return Ok(new { status = "started", generation_id = id.ToString() });
    }

    [HttpGet("brief-generation-status")]
    [RequireAction("Tab: Dashboards -> Unified Brief")]
    public IActionResult GetUnifiedBriefGenerationStatus([FromQuery(Name = "generation_id")] string? generationId)
    {
        if (string.IsNullOrWhiteSpace(generationId))
        {
            return UnprocessableEntity(new { detail = "generation_id is required." });
        }
        if (!Guid.TryParse(generationId, out var id))
        {
            return Ok(new { status = "unknown" });
        }
        return unifiedBriefGeneration.GetProgress(id) is { } progress
            ? Ok(progress)
            : Ok(new { status = "unknown" });
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

    [HttpPost("articles/generate-bluf")]
    [RequireAction("Tab: Dashboards -> Operational")]
    [RequireAction("Action: Trigger AI Functions")]
    public async Task<IActionResult> GenerateArticleBluf(
        [FromQuery(Name = "article_id")] int articleId = 0,
        CancellationToken cancellationToken = default)
    {
        if (articleId < 0)
        {
            return UnprocessableEntity(new { detail = "article_id must be non-negative." });
        }
        var result = await blufCommands.GenerateAsync(articleId, cancellationToken);
        return result.Success
            ? Ok(new { status = "ok", bluf = result.Bluf })
            : Ok(new { status = "error", message = result.Message });
    }

    [HttpPost("generate-rolling-summary")]
    [RequireAction("Tab: Dashboards -> Operational")]
    [RequireAction("Action: Generate Reports")]
    public async Task<IActionResult> GenerateRollingSummary(CancellationToken cancellationToken)
    {
        var result = await sitrepActions.RefreshBriefingAsync(cancellationToken);
        return result.Success
            ? Ok(new { status = "ok", summary = result.Content })
            : Ok(new { status = "error", message = result.Content });
    }

    [HttpPost("generate-scoring-rationale")]
    [RequireAction("Tab: Dashboards -> Global Risk")]
    [RequireAction("Action: Trigger AI Functions")]
    public async Task<IActionResult> GenerateScoringRationale(
        [FromBody] RcaSitrepActionRequest? request,
        CancellationToken cancellationToken)
    {
        var result = await sitrepActions.GenerateScoringRationaleAsync(
            request?.ToIntelInput() ?? new AiopsScoringRationaleInput("UNKNOWN", [], [], []),
            cancellationToken);
        return result.Success
            ? Ok(new { status = "ok", report = result.Content })
            : Ok(new { status = "error", message = result.Content });
    }
}
