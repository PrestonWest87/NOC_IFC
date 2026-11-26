using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/threat")]
[RequirePage("Threat Telemetry")]
public sealed class ThreatController(
    CisaKevQueries kev,
    ThreatArticleQueries articles,
    ThreatStatusQueries threatStatus) : ControllerBase
{
    [HttpGet("cloud-outages")]
    [RequireAction("Tab: Threat Telemetry -> Cloud Services")]
    public async Task<IActionResult> ListCloudOutages(
        [FromQuery(Name = "active_only")] bool activeOnly = true,
        [FromQuery(Name = "days_back")] int daysBack = 7,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var outages = await threatStatus.GetCloudOutagesAsync(activeOnly, daysBack, cancellationToken);
            return Ok(outages.Select(CloudOutageResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("microsoft-365-status")]
    [RequireAction("Tab: Threat Telemetry -> Cloud Services")]
    public async Task<IActionResult> GetMicrosoft365Status(CancellationToken cancellationToken) =>
        Ok(Microsoft365StatusResponse.From(await threatStatus.GetMicrosoft365StatusAsync(cancellationToken)));

    [HttpGet("crime-incidents")]
    [RequireAction("Tab: Threat Telemetry -> Perimeter Crime")]
    public async Task<IActionResult> ListCrimeIncidents(
        [FromQuery(Name = "hours_back")] int hoursBack = 24,
        [FromQuery(Name = "max_distance")] double maxDistance = 1.0,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var incidents = await threatStatus.GetRecentCrimesAsync(hoursBack, maxDistance, cancellationToken);
            return Ok(incidents.Select(CrimeIncidentResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("articles")]
    [RequireAction("Tab: Threat Telemetry -> RSS Triage")]
    public async Task<IActionResult> ListArticles(
        [FromQuery] string category = "live",
        [FromQuery(Name = "cat_filter")] string categoryFilter = "All",
        [FromQuery] int page = 1,
        [FromQuery(Name = "page_size")] int pageSize = 20,
        [FromQuery(Name = "search_term")] string? searchTerm = null,
        [FromQuery(Name = "min_score")] int minimumScore = 0,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await articles.GetPageAsync(
                category, categoryFilter, page, pageSize, searchTerm, minimumScore, cancellationToken);
            return Ok(ThreatArticlePageResponse.From(result));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("articles/{articleId:int}")]
    [RequireAction("Tab: Threat Telemetry -> RSS Triage")]
    public async Task<IActionResult> GetArticle(int articleId, CancellationToken cancellationToken)
    {
        var article = await articles.GetDetailAsync(articleId, cancellationToken);
        return article is null
            ? Ok(new { error = "Article not found" })
            : Ok(ThreatArticleResponse.From(article));
    }

    [HttpGet("cves")]
    [RequireAction("Tab: Threat Telemetry -> CISA KEV")]
    public async Task<IActionResult> ListCves(
        [FromQuery] int limit = 50,
        [FromQuery(Name = "days_back")] int daysBack = 30,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 200)
        {
            return UnprocessableEntity(new { detail = "limit must be between 1 and 200." });
        }
        if (daysBack is < 1 or > 365)
        {
            return UnprocessableEntity(new { detail = "days_back must be between 1 and 365." });
        }

        var entries = await kev.GetRecentAsync(limit, daysBack, cancellationToken);
        return Ok(entries.Select(CisaKevResponse.From).ToArray());
    }
}
