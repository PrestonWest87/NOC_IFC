using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/hunting")]
[RequirePage("Threat Hunting & IOCs")]
public sealed class ThreatHuntingController(ThreatHuntingQueries hunting) : ControllerBase
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
}
