using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.BackupRestore;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/restore-status")]
public sealed class RestoreStatusController(IRestoreMaintenanceControl control) : ControllerBase
{
    [HttpPost]
    public IActionResult GetStatus([FromBody] JsonObject? body)
    {
        var restoreId = body?["restore_id"] is JsonValue value && value.TryGetValue<string>(out var id)
            ? id
            : "";
        var status = control.GetRestoreStatus(restoreId);
        return status is null
            ? NotFound(new { detail = "Restore status not found." })
            : Ok(RestoreStatusResponse.From(status));
    }
}
