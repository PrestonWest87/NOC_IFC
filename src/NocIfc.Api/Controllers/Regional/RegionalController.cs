using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Identity;
using NocIfc.Application.Features.Regional;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers.Regional;

[ApiController]
[Route("api/v1/regional")]
[RequirePage("Regional Grid")]
public sealed class RegionalController(
    FacilityDirectoryCommands facilities,
    SiteTypeQueries siteTypes,
    RegionalWeatherPreferenceCommands weatherPreferences) : ControllerBase
{
    [HttpGet("locations")]
    [RequireAnyAction(
        "Tab: Regional Grid -> Geospatial Map",
        "Tab: Regional Grid -> Executive Dash",
        "Tab: Regional Grid -> Hazard Analytics",
        "Tab: Regional Grid -> Location Matrix",
        "Tab: Regional Grid -> Weather Alerts Log",
        "Tab: Regional Grid -> Atmos Weather")]
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

    [HttpGet("site-types")]
    public async Task<IActionResult> GetSiteTypes(CancellationToken cancellationToken) =>
        Ok(await siteTypes.ExecuteAsync(cancellationToken));

    [HttpGet("weather-prefs")]
    [RequireAction("Tab: Regional Grid -> Atmos Weather")]
    public async Task<IActionResult> GetWeatherPreferences(CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        return Ok(await weatherPreferences.GetAsync(user.Username, cancellationToken));
    }

    [HttpPost("weather-prefs")]
    [RequireAction("Tab: Regional Grid -> Atmos Weather")]
    public async Task<IActionResult> SetWeatherPreferences(
        [FromBody] List<string?>? alerts,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        if (alerts?.Any(alert => alert is null) == true)
        {
            return UnprocessableEntity(new { detail = "alerts must contain only strings." });
        }
        await weatherPreferences.ReplaceAsync(
            user.Username,
            alerts?.Select(alert => alert!).ToArray() ?? [],
            cancellationToken);
        return Ok(new { status = "ok" });
    }
}
