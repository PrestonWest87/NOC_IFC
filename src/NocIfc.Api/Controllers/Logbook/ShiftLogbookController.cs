using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Logbook;

namespace NocIfc.Api.Controllers.Logbook;

[ApiController]
[Route("api/v1/logbook")]
[RequirePage("Shift Logbook")]
public sealed class ShiftLogbookController(ShiftLogbookCommands logbook) : ControllerBase
{
    [HttpGet("entries")]
    [RequireAnyAction("Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History")]
    public async Task<IActionResult> GetEntries(
        [FromQuery(Name = "role_filter")] string roleFilter = "All",
        [FromQuery(Name = "start_date")] string? startDate = null,
        [FromQuery(Name = "end_date")] string? endDate = null,
        CancellationToken cancellationToken = default)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var entries = await logbook.GetEntriesAsync(user, roleFilter, startDate, endDate, cancellationToken);
            return Ok(entries.Select(ShiftLogEntryResponse.From).ToArray());
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("roles")]
    public async Task<IActionResult> GetRoles(CancellationToken cancellationToken) =>
        Ok((await logbook.GetRoleNamesAsync(cancellationToken))
            .Select(name => new ShiftLogbookRoleResponse(name)).ToArray());

    [HttpPost("entries")]
    [RequireAction("Tab: Shift Log -> Active Shift")]
    [RequireAction("Action: Submit Shift Log")]
    public async Task<IActionResult> CreateEntry(
        [FromQuery] string role = "analyst",
        [FromQuery(Name = "shift_period")] string shiftPeriod = "Morning",
        [FromQuery] string content = "",
        [FromQuery(Name = "custom_date")] string? customDate = null,
        CancellationToken cancellationToken = default)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            await logbook.CreateAsync(user, role, shiftPeriod, content, customDate, cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPatch("entries/{entryId:int}")]
    [RequireAnyAction("Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History")]
    [RequireAction("Action: Submit Shift Log")]
    public async Task<IActionResult> UpdateEntry(
        int entryId,
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] JsonObject? data,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        bool? isDeleted = null;
        if (data?.TryGetPropertyValue("is_deleted", out var value) == true && value is not null)
        {
            if (value is not JsonValue jsonValue || !jsonValue.TryGetValue<bool>(out var parsed))
            {
                return UnprocessableEntity(new { detail = "is_deleted must be a boolean." });
            }
            isDeleted = parsed;
        }

        var result = await logbook.UpdateDeletedAsync(user, entryId, isDeleted, cancellationToken);
        if (result.Forbidden)
        {
            const string permission = "Action: Manage Shift Logs";
            return StatusCode(StatusCodes.Status403Forbidden, new
            {
                detail = new
                {
                    code = "permission_denied",
                    scope = "action",
                    permission,
                    message = $"Missing permission: {permission}",
                },
            });
        }
        return result.Status == "error"
            ? Ok(new { status = result.Status, message = result.Message })
            : Ok(new { status = result.Status, id = result.Id, is_deleted = result.IsDeleted });
    }
}
