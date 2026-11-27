using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Nodes;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Abstractions.BackupRestore;
using NocIfc.Domain.BackupRestore;
using NocIfc.Api.Services;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/admin")]
[RequireAdministrator]
public sealed class BackupRestoreController(
    IBackupManager backups,
    IBackupDataStore legacyData,
    RestoreCoordinator restores) : ControllerBase
{
    [HttpGet("backup")]
    public async Task<IActionResult> GetLegacyBackup(CancellationToken cancellationToken) =>
        Ok(await legacyData.GetLegacySettingsBackupAsync(cancellationToken));

    [HttpPost("restore")]
    public async Task<IActionResult> RestoreLegacyBackup(
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        try
        {
            await legacyData.RestoreLegacySettingsBackupAsync(body ?? new JsonObject(), cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("export-all")]
    public async Task<IActionResult> ExportAll(CancellationToken cancellationToken) =>
        Ok(await legacyData.ExportAllTablesAsync(cancellationToken));

    [HttpPost("import-all")]
    public async Task<IActionResult> ImportAll(
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        var data = body?.DeepClone().AsObject() ?? new JsonObject();
        var merge = false;
        if (data.TryGetPropertyValue("_merge", out var mergeNode))
        {
            if (mergeNode is not JsonValue scalar || !scalar.TryGetValue<bool>(out merge))
            {
                return BadRequest(new { detail = "_merge must be a boolean value." });
            }
            data.Remove("_merge");
        }
        try
        {
            return Ok(new
            {
                status = "ok",
                counts = await legacyData.ImportAllTablesAsync(data, merge, cancellationToken),
            });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("upload-db")]
    [RequestSizeLimit(100L * 1024 * 1024 * 1024)]
    [RequestFormLimits(MultipartBodyLengthLimit = 100L * 1024 * 1024 * 1024)]
    public async Task<IActionResult> UploadDatabaseRows(
        [FromForm] IFormFile? file,
        CancellationToken cancellationToken)
    {
        if (file is null || !file.FileName.EndsWith(".db", StringComparison.Ordinal))
        {
            return BadRequest(new { detail = "Uploaded file must have a .db extension." });
        }
        var maxBytes = backups.GetStatus().MaxBytes;
        if (file.Length <= 0 || file.Length > maxBytes)
        {
            return BadRequest(new { detail = "Uploaded database file is empty or exceeds BACKUP_MAX_BYTES." });
        }
        var temporary = Path.Combine(Path.GetTempPath(), $"noc-ifc-import-{Guid.NewGuid():N}.db");
        try
        {
            await using (var destination = new FileStream(
                temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.WriteThrough))
            {
                if (!OperatingSystem.IsWindows())
                {
                    System.IO.File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                await file.CopyToAsync(destination, cancellationToken);
                await destination.FlushAsync(cancellationToken);
            }
            var counts = await legacyData.ImportDatabaseRowsAsync(temporary, cancellationToken);
            return Ok(new { status = "ok", counts });
        }
        catch (Exception exception) when (exception is ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            return BadRequest(new { detail = $"Database import failed: {exception.Message}" });
        }
        finally
        {
            System.IO.File.Delete(temporary);
        }
    }

    [HttpGet("backups/status")]
    public IActionResult GetStatus()
    {
        try
        {
            return Ok(BackupStatusResponse.From(backups.GetStatus()));
        }
        catch (BackupException exception)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { detail = exception.Message });
        }
    }

    [HttpGet("backups")]
    public IActionResult GetBackups() => Ok(new
    {
        backups = backups.ListBackups().Select(BackupEntryResponse.From).ToArray(),
    });

    [HttpPost("backups")]
    public IActionResult CreateBackup()
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            return Ok(BackupEntryResponse.From(backups.CreateBackup("manual", createdBy: user.Username)));
        }
        catch (BackupException exception)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { detail = exception.Message });
        }
    }

    [HttpGet("backups/{backupId}/download")]
    public IActionResult DownloadBackup(string backupId)
    {
        try
        {
            var stream = backups.OpenBackupRead(backupId);
            Response.Headers.CacheControl = "no-store";
            Response.Cookies.Delete("noc_backup_download", CookieOptionsFor(backupId));
            return File(stream, "application/octet-stream", backupId, enableRangeProcessing: false);
        }
        catch (BackupException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
    }

    [HttpPost("backups/{backupId}/download-link")]
    public IActionResult CreateDownloadLink(string backupId)
    {
        var token = AuthenticatedUserContext.GetToken(HttpContext);
        if (string.IsNullOrWhiteSpace(token)) return Unauthorized();
        try
        {
            using var stream = backups.OpenBackupRead(backupId);
            Response.Cookies.Append("noc_backup_download", token, CookieOptionsFor(backupId));
            return Ok(new { url = $"/api/v1/admin/backups/{Uri.EscapeDataString(backupId)}/download" });
        }
        catch (BackupException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
    }

    [HttpDelete("backups/{backupId}")]
    public IActionResult DeleteBackup(string backupId)
    {
        try
        {
            backups.DeleteBackup(backupId);
            return Ok(new { status = "deleted" });
        }
        catch (BackupException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("backups/staged")]
    public IActionResult GetStagedBackups() => Ok(new
    {
        backups = backups.ListStagedBackups().Select(StagedBackupEntryResponse.From).ToArray(),
    });

    [HttpPost("backups/staged")]
    [RequestSizeLimit(100L * 1024 * 1024 * 1024)]
    [RequestFormLimits(MultipartBodyLengthLimit = 100L * 1024 * 1024 * 1024)]
    public IActionResult StageBackup([FromForm] IFormFile? file)
    {
        if (file is null) return BadRequest(new { detail = "A backup file is required." });
        try
        {
            using var stream = file.OpenReadStream();
            return Ok(StagedBackupEntryResponse.From(backups.StageUpload(stream)));
        }
        catch (BackupException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpDelete("backups/staged/{stageId}")]
    public IActionResult DeleteStagedBackup(string stageId)
    {
        try
        {
            backups.DeleteStagedBackup(stageId);
            return Ok(new { status = "deleted" });
        }
        catch (BackupException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
    }

    [HttpPost("backups/staged/{stageId}/restore")]
    public IActionResult StartRestore(string stageId)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            var restoreId = restores.StartRestore(stageId, user.Username);
            return Accepted(new { status = "started", restore_id = restoreId });
        }
        catch (BackupException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
        catch (RestoreInProgressException exception)
        {
            return Conflict(new { detail = exception.Message });
        }
        catch (Exception)
        {
            return StatusCode(StatusCodes.Status500InternalServerError,
                new { detail = "Unable to start the restore service." });
        }
    }

    private CookieOptions CookieOptionsFor(string backupId)
    {
        var secure = Request.IsHttps || string.Equals(
            Request.Headers["X-Forwarded-Proto"].ToString(), "https", StringComparison.OrdinalIgnoreCase);
        return new CookieOptions
        {
            Path = $"/api/v1/admin/backups/{backupId}/download",
            MaxAge = TimeSpan.FromSeconds(60),
            HttpOnly = true,
            Secure = secure,
            SameSite = SameSiteMode.Strict,
        };
    }
}
