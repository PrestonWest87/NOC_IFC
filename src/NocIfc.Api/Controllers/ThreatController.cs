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
    CisaKevSyncCommands kevSync,
    CloudStatusSyncCommands cloudStatusSync,
    CrimeDataSyncCommands crimeSync,
    RssFeedFetchCommands rssSync,
    ThreatArticleQueries articles,
    ThreatStatusQueries threatStatus,
    ThreatHuntingCommands huntingCommands,
    ILogger<ThreatController> logger) : ControllerBase
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

    [HttpPost("sync-cisa-kev")]
    [RequireAction("Tab: Threat Telemetry -> CISA KEV")]
    [RequireAction("Action: Manually Sync Data")]
    public async Task<IActionResult> SyncCisaKev(CancellationToken cancellationToken)
    {
        try
        {
            await kevSync.ExecuteAsync(cancellationToken);
            return Ok(new { status = "ok", message = "CISA KEV synced." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Manual CISA KEV synchronization failed.");
            return Ok(new { status = "error", message = exception.Message });
        }
    }

    [HttpPost("sync-cloud-status")]
    [RequireAction("Tab: Threat Telemetry -> Cloud Services")]
    [RequireAction("Action: Manually Sync Data")]
    public async Task<IActionResult> SyncCloudStatus(CancellationToken cancellationToken)
    {
        try
        {
            var result = await cloudStatusSync.ExecuteAsync(cancellationToken);
            logger.LogInformation(
                "Cloud status sync added {Added}, resolved {Resolved}, filtered {Filtered}; failed providers: {FailedProviders}.",
                result.AddedCount, result.ResolvedCount, result.FilteredCount, string.Join(", ", result.FailedProviders));
            return Ok(new { status = "ok", message = "Cloud status synced." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Manual cloud status synchronization failed.");
            return Ok(new { status = "error", message = exception.Message });
        }
    }

    [HttpPost("fetch-crime-data")]
    [RequireAction("Tab: Threat Telemetry -> Perimeter Crime")]
    [RequireAction("Action: Manually Sync Data")]
    public async Task<IActionResult> FetchCrimeData(CancellationToken cancellationToken)
    {
        try
        {
            var result = await crimeSync.ExecuteAsync(cancellationToken);
            logger.LogInformation(
                "Crime data sync added {Added} incidents and dispatched {Alerts} perimeter alerts.",
                result.AddedCount, result.AlertsDispatched);
            return Ok(new { status = "ok", message = "Crime data fetched." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Manual crime data fetch failed.");
            return Ok(new { status = "error", message = "Crime fetch failed." });
        }
    }

    [HttpPost("fetch-feeds")]
    [RequireAction("Tab: Threat Telemetry -> RSS Triage")]
    [RequireAction("Action: Manually Sync Data")]
    public async Task<IActionResult> FetchFeeds(CancellationToken cancellationToken)
    {
        try
        {
            var result = await rssSync.ExecuteAsync(cancellationToken);
            logger.LogInformation(
                "Manual RSS fetch added {Added} articles, failed feeds {Failed}, removed duplicates {Duplicates}.",
                result.AddedCount, result.FailedFeeds, result.RemovedDuplicates);
            return Ok(new { status = "ok", message = "Feeds fetched successfully." });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Manual RSS fetch failed.");
            return Ok(new { status = "error", message = exception.Message });
        }
    }

    [HttpPost("sync-elastic-cache")]
    [RequireAction("Tab: Reporting -> Elastic SIEM Report")]
    [RequireAction("Action: Manually Sync Data")]
    public async Task<IActionResult> SyncElasticCache(
        [FromQuery(Name = "hours_back")] int hoursBack = 24,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await huntingCommands.SyncElasticCacheAsync(hoursBack, cancellationToken);
            if (result.Status is "error" or "skipped")
            {
                return StatusCode(result.Status == "skipped" ? 503 : 502,
                    new { detail = result.Message ?? "Elastic cache sync failed." });
            }
            return Ok(new { status = "ok", message = "Elastic cache synced.", result = new { status = result.Status, imported = result.Imported } });
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("generate-siem-triage")]
    [RequireAction("Tab: Reporting -> Elastic SIEM Report")]
    [RequireAction("Action: Trigger AI Functions")]
    public async Task<IActionResult> GenerateSiemTriage(
        [FromBody] SiemTriageRequest? request,
        CancellationToken cancellationToken)
    {
        try
        {
            var events = request?.ToEvents() ?? throw new ArgumentException("Provide between 1 and 50 SIEM events.");
            var summary = await huntingCommands.GenerateSiemTriageAsync(events, cancellationToken);
            return Ok(new { summary = summary.Length == 0 ? "Unable to generate triage summary." : summary });
        }
        catch (SiemTriagePayloadTooLargeException exception)
        {
            return StatusCode(413, new { detail = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
