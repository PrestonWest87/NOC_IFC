using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Text.Json.Nodes;
using NocIfc.Api.Authorization;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/admin")]
[RequireAdministrator]
public sealed class DangerZoneController(DangerZoneCommands dangerZone) : ControllerBase
{
    [HttpDelete("record")]
    public async Task<IActionResult> DeleteRecord(
        [FromQuery(Name = "model_name")] string modelName = "",
        [FromQuery(Name = "record_id")] int recordId = 0,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await dangerZone.DeleteRecordAsync(modelName, recordId, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("nuke")]
    public async Task<IActionResult> ClearTables(
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] JsonArray? tables,
        CancellationToken cancellationToken)
    {
        try
        {
            var modelNames = new List<string>();
            foreach (var item in tables ?? [])
            {
                if (item is not JsonValue scalar || !scalar.TryGetValue<string>(out var name))
                {
                    throw new ArgumentException("Table names must be strings.");
                }
                modelNames.Add(name);
            }
            await dangerZone.ClearTablesAsync(modelNames, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("nuke/crime")]
    public async Task<IActionResult> ClearCrimeData(CancellationToken cancellationToken)
    {
        await dangerZone.ClearCrimeDataAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("nuke/weather")]
    public async Task<IActionResult> ClearWeatherData(CancellationToken cancellationToken)
    {
        await dangerZone.ClearWeatherDataAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("maintenance")]
    public async Task<IActionResult> RunDatabaseMaintenance(CancellationToken cancellationToken)
    {
        await dangerZone.RunDatabaseMaintenanceAsync(cancellationToken);
        return Ok(new { status = "ok" });
    }
}
