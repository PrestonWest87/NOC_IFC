using Microsoft.AspNetCore.Mvc;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Infrastructure.Persistence.Sqlite;

namespace NocIfc.Api.Controllers;

[ApiController]
public sealed class DiagnosticsController(
    SqliteReadinessProbe database,
    IRestoreMaintenanceControl restore,
    ILogger<DiagnosticsController> logger) : ControllerBase
{
    [HttpGet("/health")]
    public IActionResult Health() => Ok(new { status = "ok", ws_clients = 0 });

    [HttpGet("/ready")]
    public async Task<IActionResult> Readiness(CancellationToken cancellationToken)
    {
        if (restore.MaintenanceRequested)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { detail = "database restore in progress" });
        }
        try
        {
            if (await database.IsReadyAsync(cancellationToken))
            {
                return Ok(new { status = "ready" });
            }

            logger.LogWarning(
                "SQLite schema is not at expected Alembic revision {ExpectedRevision}.",
                SqliteReadinessProbe.ExpectedSchemaRevision);
        }
        catch (Exception exception)
        {
            logger.LogWarning(exception, "SQLite readiness check failed.");
        }

        return StatusCode(StatusCodes.Status503ServiceUnavailable, new { detail = "database unavailable" });
    }
}
