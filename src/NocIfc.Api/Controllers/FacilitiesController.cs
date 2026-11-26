using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/settings")]
[RequirePage("Settings & Admin")]
public sealed class FacilitiesController(FacilityDirectoryCommands facilities) : ControllerBase
{
    [HttpGet("facilities")]
    [RequireAction("Tab: Settings -> Facility Locations")]
    public async Task<IActionResult> GetLocations(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        var locations = await facilities.GetLocationsAsync(user, cancellationToken);
        return Ok(locations.Select(MonitoredLocationResponse.From).ToArray());
    }
}

[ApiController]
[Route("api/v1/admin")]
public sealed class FacilitiesAdminController(FacilityDirectoryCommands facilities) : ControllerBase
{
    [HttpGet("location")]
    [RequireAdministrator]
    public async Task<IActionResult> GetAllLocations(CancellationToken cancellationToken) =>
        Ok((await facilities.GetAdminLocationsAsync(cancellationToken)).Select(MonitoredLocationResponse.From).ToArray());

    [HttpGet("location/{locationId:int}/contacts")]
    [RequireAdministrator]
    public async Task<IActionResult> GetContacts(int locationId, CancellationToken cancellationToken)
    {
        var contacts = await facilities.GetSiteContactsAsync(locationId, cancellationToken);
        return contacts is null
            ? NotFound(new { detail = "Monitored location not found." })
            : Ok(SiteContactsResponse.From(contacts));
    }

    [HttpPut("location/{locationId:int}/contacts")]
    [RequireAdministrator]
    public async Task<IActionResult> ReplaceContacts(
        int locationId,
        [FromBody] SiteContactsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var contacts = await facilities.ReplaceSiteContactsAsync(locationId, request.ToInputs(), cancellationToken);
            return contacts is null
                ? NotFound(new { detail = "Monitored location not found." })
                : Ok(new SiteContactsUpdateResponse("ok", contacts.Select(SiteContactResponse.From).ToArray()));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPut("location")]
    [RequireAdministrator]
    public async Task<IActionResult> UpdateLocations(
        [FromBody] List<LocationEditRequest> locations,
        CancellationToken cancellationToken)
    {
        try
        {
            await facilities.UpdateLocationsAsync(locations.Select(location => location.ToRow()).ToArray(), cancellationToken);
            return Ok(new { status = "ok" });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPost("location/import")]
    [RequireAdministrator]
    public async Task<IActionResult> ImportLocations(
        [FromBody] List<LocationImportRequest> locations,
        [FromQuery] string mode = "add",
        CancellationToken cancellationToken = default)
    {
        try
        {
            var count = await facilities.ImportLocationsAsync(
                locations.Select(location => location.ToRow()).ToArray(), mode, cancellationToken);
            return Ok(new { status = "ok", mode, count });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }
}
