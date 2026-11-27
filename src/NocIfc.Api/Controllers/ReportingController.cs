using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Reporting;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/reporting")]
[RequirePage("Reporting & Briefings")]
public sealed class ReportingController(SavedReportCommands reports, DailyBriefingQueries briefings) : ControllerBase
{
    [HttpGet("daily-briefings")]
    [RequireAction("Tab: Reporting -> Daily Fusion")]
    public async Task<IActionResult> GetDailyBriefings(CancellationToken cancellationToken) =>
        Ok((await briefings.GetAllAsync(cancellationToken)).Select(DailyBriefingResponse.From).ToArray());

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
