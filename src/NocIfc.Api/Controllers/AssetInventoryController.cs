using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/admin/assets")]
[RequireAdministrator]
public sealed class AssetInventoryController(AssetInventoryCommands inventory) : ControllerBase
{
    [HttpPost("software")]
    public async Task<IActionResult> ImportSoftware(
        [FromBody] AssetCsvImportRequest request,
        CancellationToken cancellationToken)
    {
        var result = await inventory.ImportSoftwareCsvAsync(request.CsvBody ?? "", cancellationToken);
        return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
    }

    [HttpPost("hardware")]
    public async Task<IActionResult> ImportHardware(
        [FromBody] AssetCsvImportRequest request,
        CancellationToken cancellationToken)
    {
        var result = await inventory.ImportHardwareCsvAsync(request.CsvBody ?? "", cancellationToken);
        return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
    }
}
