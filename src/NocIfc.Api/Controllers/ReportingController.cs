using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Api.Services;
using NocIfc.Application.Features.Dashboard;
using NocIfc.Application.Features.Reporting;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/reporting")]
[RequirePage("Reporting & Briefings")]
public sealed class ReportingController(
    SavedReportCommands reports,
    DailyBriefingQueries briefings,
    DailyFusionCommands dailyFusion,
    ReportingBroadcastCommands broadcasts,
    ThreatHuntingQueries threatHunting,
    CustomReportGenerationState reportGeneration,
    ExecutiveIntelQueries executiveIntel) : ControllerBase
{
    [HttpGet("executive-intel")]
    [RequireAction("Tab: Reporting -> Daily Fusion")]
    public async Task<IActionResult> GetExecutiveIntel(CancellationToken cancellationToken) =>
        Ok(ExecutiveIntelResponse.From(await executiveIntel.GetForReportingAsync(cancellationToken)));

    [HttpGet("daily-briefings")]
    [RequireAction("Tab: Reporting -> Daily Fusion")]
    public async Task<IActionResult> GetDailyBriefings(CancellationToken cancellationToken) =>
        Ok((await briefings.GetAllAsync(cancellationToken)).Select(DailyBriefingResponse.From).ToArray());

    [HttpPost("generate-daily")]
    [RequireAction("Tab: Reporting -> Daily Fusion")]
    [RequireAction("Action: Generate Reports")]
    public async Task<IActionResult> GenerateDaily(CancellationToken cancellationToken)
    {
        var result = await dailyFusion.GenerateAsync(cancellationToken);
        return result.Success
            ? Ok(new { status = "ok", date = result.Date, content = result.Content })
            : Ok(new { status = "error", message = result.Message ?? "Report generation failed or AI is disabled." });
    }

    [HttpPost("broadcast")]
    [RequireAction("Tab: Reporting -> Daily Fusion")]
    [RequireAction("Action: Dispatch Exec Report")]
    public async Task<IActionResult> BroadcastDailyFusion(
        [FromBody] DailyFusionBroadcastRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A Daily Fusion broadcast request is required." });
        }
        try
        {
            var result = await broadcasts.BroadcastDailyFusionAsync(
                request.ReportDate ?? "", request.Content ?? "", request.Recipients ?? "", cancellationToken);
            return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("broadcast-custom")]
    [RequireAction("Tab: Reporting -> Report Builder")]
    [RequireAction("Action: Dispatch Exec Report")]
    public async Task<IActionResult> BroadcastCustom(
        [FromBody] CustomReportBroadcastRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A custom report broadcast request is required." });
        }
        try
        {
            var result = await broadcasts.BroadcastCustomAsync(
                request.Title, request.Content ?? "", request.Recipients ?? "", cancellationToken);
            return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("search-articles")]
    [RequireAction("Tab: Reporting -> Report Builder")]
    public async Task<IActionResult> SearchArticles(
        [FromBody] ReportingArticleSearchRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A search request is required." });
        }
        if (request.Target.Length > 500)
        {
            return UnprocessableEntity(new { detail = "target must be 500 characters or fewer." });
        }
        if (request.DaysBack is < 1 or > 30)
        {
            return UnprocessableEntity(new { detail = "days_back must be between 1 and 30." });
        }
        if (string.IsNullOrWhiteSpace(request.Target))
        {
            return Ok(new { status = "error", message = "Please enter a search target.", articles = Array.Empty<ReportingArticleSearchItem>() });
        }
        try
        {
            var terms = ThreatHuntingQueries.ParseSearchTerms(request.Target);
            var articles = await threatHunting.SearchArticlesAsync(request.Target.Trim(), request.DaysBack, cancellationToken);
            return Ok(new
            {
                status = "ok",
                terms,
                articles = articles.Select(ReportingArticleSearchItem.From).ToArray(),
            });
        }
        catch (ArgumentException exception)
        {
            return Ok(new { status = "error", message = exception.Message, articles = Array.Empty<ReportingArticleSearchItem>() });
        }
    }

    [HttpPost("generate-custom")]
    [RequireAction("Tab: Reporting -> Report Builder")]
    [RequireAction("Action: Generate Reports")]
    public IActionResult GenerateCustom([FromBody] CustomReportGenerationRequest? request)
    {
        if (request is null)
        {
            return UnprocessableEntity(new { detail = "A custom report request is required." });
        }

        var rawTarget = request.Target ?? "";
        var target = rawTarget.Trim();
        var articleIds = request.ArticleIds ?? [];
        var objective = request.Objective ?? "";
        var analyst = request.Analyst ?? "Unknown";
        if (rawTarget.Length > 500 || objective.Length > 4000 || analyst.Length > 120
            || request.DaysBack is < 1 or > 30 || articleIds.Count > 100)
        {
            return UnprocessableEntity(new { detail = "Custom report criteria exceed their maximum bounds." });
        }
        if (articleIds.Any(id => id <= 0))
        {
            return UnprocessableEntity(new { detail = "article_ids must contain positive integers." });
        }

        var selectedIds = articleIds.Distinct().ToArray();
        var hasTarget = target.Length > 0;
        if (!hasTarget && selectedIds.Length == 0)
        {
            return Ok(new { status = "error", message = "Please enter a target entity or select articles." });
        }
        if (hasTarget)
        {
            try
            {
                if (ThreatHuntingQueries.ParseSearchTerms(target).Count == 0)
                {
                    return Ok(new { status = "error", message = "Please enter at least one valid search term." });
                }
            }
            catch (ArgumentException exception)
            {
                return Ok(new { status = "error", message = exception.Message });
            }
        }

        var generationId = reportGeneration.Start(new CustomReportGenerationInput(
            target, request.DaysBack, selectedIds, objective, analyst));
        return Ok(new { status = "started", generation_id = generationId.ToString() });
    }

    [HttpGet("generate-custom-status")]
    [RequireAction("Tab: Reporting -> Report Builder")]
    public IActionResult GetCustomGenerationStatus([FromQuery(Name = "generation_id")] string? generationId)
    {
        if (!Guid.TryParse(generationId, out var parsedId))
        {
            return Ok(new { status = "error", message = "Invalid generation id." });
        }
        if (reportGeneration.TryTakeResult(parsedId, out var result))
        {
            return result!.Success
                ? Ok(new { status = "ok", content = result.Content })
                : Ok(new { status = "error", message = result.Message });
        }
        var progress = reportGeneration.GetProgress(parsedId);
        return progress is null
            ? Ok(new { status = "in_progress", progress = new { } })
            : Ok(new { status = "in_progress", progress });
    }

    [HttpGet("saved-reports")]
    [RequireAction("Tab: Reporting -> Shared Library")]
    public async Task<IActionResult> GetSavedReports(CancellationToken cancellationToken) =>
        Ok((await reports.GetAllAsync(cancellationToken)).Select(SavedReportResponse.From).ToArray());

    [HttpPost("save-report")]
    [RequireAction("Tab: Reporting -> Report Builder")]
    [RequireAction("Action: Dispatch Exec Report")]
    public async Task<IActionResult> SaveReport(
        [FromBody] SaveReportRequest? request,
        CancellationToken cancellationToken)
    {
        try
        {
            await reports.SaveAsync(request?.Title, request?.Author, request?.Content, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpDelete("saved-reports/{reportId:int}")]
    [RequireAction("Tab: Reporting -> Shared Library")]
    [RequireAction("Action: Dispatch Exec Report")]
    public async Task<IActionResult> DeleteSavedReport(int reportId, CancellationToken cancellationToken)
    {
        await reports.DeleteAsync(reportId, cancellationToken);
        return Ok(new { status = "ok" });
    }
}
