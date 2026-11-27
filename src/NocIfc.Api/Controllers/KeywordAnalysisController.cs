using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/keyword-analysis")]
[RequirePage("Keyword Analysis")]
public sealed class KeywordAnalysisController(
    KeywordAnalysisQueries queries,
    KeywordAnalysisCommands commands) : ControllerBase
{
    [HttpGet("overview")]
    public async Task<IActionResult> Overview(CancellationToken cancellationToken) =>
        Ok(KeywordAnalysisOverviewResponse.From(await queries.GetOverviewAsync(cancellationToken)));

    [HttpGet("keyword-stats")]
    public async Task<IActionResult> KeywordStats(
        [FromQuery(Name = "sort_by")] string sortBy = "trigger_count",
        [FromQuery] string order = "desc",
        [FromQuery] string search = "",
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetKeywordStatsAsync(sortBy, order, search, limit, cancellationToken);
            return Ok(result.Select(KeywordAnalysisStatResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("category-distribution")]
    public async Task<IActionResult> CategoryDistribution(
        [FromQuery] int days = 0,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetCategoryDistributionAsync(days, cancellationToken);
            return Ok(result.Select(KeywordCategoryDistributionResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("timeline")]
    public async Task<IActionResult> Timeline(
        [FromQuery] string? keyword = "",
        [FromQuery] int days = 30,
        [FromQuery] string interval = "day",
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetTimelineAsync(keyword, days, interval, cancellationToken);
            return Ok(result.Select(KeywordAnalysisTimelineResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("keyword-articles")]
    public async Task<IActionResult> KeywordArticles(
        [FromQuery] string? keyword,
        [FromQuery] int limit = 50,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetKeywordArticlesAsync(keyword, limit, cancellationToken);
            return Ok(result.Select(KeywordAnalysisArticleResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("score-distribution")]
    public async Task<IActionResult> ScoreDistribution(
        [FromQuery] int days = 0,
        [FromQuery(Name = "bucket_size")] int bucketSize = 10,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetScoreDistributionAsync(days, bucketSize, cancellationToken);
            return Ok(result.Select(KeywordScoreBucketResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("category-keyword-matrix")]
    public async Task<IActionResult> CategoryKeywordMatrix(
        [FromQuery(Name = "top_n")] int topN = 20,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return Ok(KeywordCategoryMatrixResponse.From(
                await queries.GetCategoryKeywordMatrixAsync(topN, cancellationToken)));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("category-details")]
    public async Task<IActionResult> CategoryDetails(
        [FromQuery] string? category,
        [FromQuery] int days = 0,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await queries.GetCategoryDetailsAsync(category, days, cancellationToken);
            return Ok(KeywordCategoryDetailsResponse.From(result));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("recategorize")]
    [RequireAction("Action: Trigger AI Functions")]
    public async Task<IActionResult> Recategorize(CancellationToken cancellationToken) =>
        Ok(KeywordRecategorizationResponse.From(await commands.RecategorizeAsync(cancellationToken)));
}
