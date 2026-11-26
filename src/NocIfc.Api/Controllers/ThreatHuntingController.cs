using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/hunting")]
[RequirePage("Threat Hunting & IOCs")]
public sealed class ThreatHuntingController(
    ThreatHuntingQueries hunting,
    ThreatHuntingCommands commands) : ControllerBase
{
    [HttpGet("iocs")]
    [RequireAction("Tab: Threat Hunting -> Global IOC Matrix")]
    public async Task<IActionResult> GetIocs(
        [FromQuery(Name = "days_back")] int daysBack = 3,
        [FromQuery] int limit = 1000,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var iocs = await hunting.GetIocsAsync(daysBack, limit, cancellationToken);
            return Ok(iocs.Select(ThreatHuntingIocResponse.From).ToArray());
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("osint-pivot")]
    [RequireAction("Tab: Threat Hunting -> Global IOC Matrix")]
    public IActionResult GetOsintPivot(
        [FromQuery(Name = "ioc_type")] string iocType = "",
        [FromQuery(Name = "ioc_value")] string iocValue = "") =>
        Ok(new { link = hunting.GetOsintPivotLink(iocType, iocValue) });

    [HttpGet("search-articles")]
    [RequireAction("Tab: Threat Hunting -> Deep Hunt Builder")]
    public async Task<IActionResult> SearchArticles(
        [FromQuery] string target = "",
        [FromQuery(Name = "days_back")] int daysBack = 3,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var results = await hunting.SearchArticlesAsync(target, daysBack, cancellationToken);
            return Ok(results.Select(ThreatArticleResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("elastic-events")]
    [RequireAction("Tab: Reporting -> Elastic SIEM Report")]
    public async Task<IActionResult> GetElasticEvents(
        [FromQuery(Name = "hours_back")] int hoursBack = 24,
        [FromQuery] int page = 1,
        [FromQuery(Name = "page_size")] int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await hunting.GetElasticEventsAsync(hoursBack, page, pageSize, cancellationToken);
            return Ok(ElasticEventsPageResponse.From(result));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
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
            var result = await commands.SyncElasticCacheAsync(hoursBack, cancellationToken);
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
            var summary = await commands.GenerateSiemTriageAsync(events, cancellationToken);
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
