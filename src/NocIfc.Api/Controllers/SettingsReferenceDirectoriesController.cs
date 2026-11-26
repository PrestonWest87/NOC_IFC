using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;
using NocIfc.Application.Features.Threat;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/settings")]
[RequirePage("Settings & Admin")]
public sealed class SettingsReferenceDirectoriesController(
    SettingsReferenceDirectoryCommands directories,
    RssSettingsCommands rssSettings) : ControllerBase
{
    [HttpGet("rss")]
    [RequireAction("Tab: Settings -> RSS Sources")]
    public async Task<IActionResult> GetRssSettings(CancellationToken cancellationToken) =>
        Ok(RssSettingsResponse.From(await rssSettings.GetAsync(cancellationToken)));

    [HttpGet("email-contacts")]
    [RequireAction("Tab: Settings -> Email Contacts")]
    public async Task<IActionResult> GetEmailContacts(CancellationToken cancellationToken)
    {
        var fiber = await directories.GetFiberAsync(cancellationToken);
        var onpage = await directories.GetOnpageAsync(cancellationToken);
        return Ok(EmailContactsDirectoryResponse.From(fiber, onpage));
    }

    [HttpGet("network-orders")]
    [RequireAction("Tab: Settings -> Network Orders & Circuits")]
    public async Task<IActionResult> GetNetworkOrders(CancellationToken cancellationToken) =>
        Ok(NetworkOrdersDirectoryResponse.From(await directories.GetNetworkOrdersAsync(cancellationToken)));
}

[ApiController]
[Route("api/v1/admin")]
public sealed class SettingsReferenceDirectoriesAdminController(
    SettingsReferenceDirectoryCommands directories,
    RssSettingsCommands rssSettings) : ControllerBase
{
    [HttpPost("keywords/bulk")]
    [RequireAdministrator]
    public async Task<IActionResult> AddBulkKeywords(
        [FromQuery(Name = "raw_text")] string rawText = "",
        CancellationToken cancellationToken = default)
    {
        await rssSettings.AddBulkKeywordsAsync(rawText, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPost("feeds/bulk")]
    [RequireAdministrator]
    public async Task<IActionResult> AddBulkFeeds(
        [FromQuery(Name = "raw_text")] string rawText = "",
        CancellationToken cancellationToken = default)
    {
        await rssSettings.AddBulkFeedsAsync(rawText, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPatch("keywords/{keywordId:int}")]
    [RequireAdministrator]
    public async Task<IActionResult> UpdateKeywordWeight(
        int keywordId,
        [FromBody] KeywordWeightUpdateRequest request,
        CancellationToken cancellationToken)
    {
        if (request.Weight is null)
        {
            return BadRequest(new { detail = "weight must be an integer between 1 and 100" });
        }
        try
        {
            var keyword = await rssSettings.UpdateKeywordWeightAsync(keywordId, request.Weight.Value, cancellationToken);
            return Ok(new KeywordWeightUpdateResponse("ok", KeywordDirectoryResponse.From(keyword)));
        }
        catch (ArgumentOutOfRangeException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
        catch (KeyNotFoundException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
    }

    [HttpDelete("keywords/{keywordId:int}")]
    [RequireAdministrator]
    public async Task<IActionResult> DeleteKeyword(int keywordId, CancellationToken cancellationToken)
    {
        await rssSettings.DeleteKeywordAsync(keywordId, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpDelete("feeds/{feedId:int}")]
    [RequireAdministrator]
    public async Task<IActionResult> DeleteFeed(int feedId, CancellationToken cancellationToken)
    {
        await rssSettings.DeleteFeedAsync(feedId, cancellationToken);
        return Ok(new { status = "ok" });
    }

    [HttpPut("email-contacts/fiber")]
    [RequireAdministrator]
    public async Task<IActionResult> ReplaceFiber(
        [FromBody] FiberEmailContactsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var contacts = await directories.ReplaceFiberAsync(request.ToInputs(), actor.Id, cancellationToken);
            return Ok(new FiberEmailContactsUpdateResponse(
                "ok", contacts.Select(FiberEmailContactResponse.From).ToArray()));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("email-contacts/fiber/import")]
    [RequireAdministrator]
    public async Task<IActionResult> ImportFiber(
        [FromBody] SettingsDirectoryCsvImportRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var (csvText, mode) = request.ToImport();
            var result = await directories.ImportFiberAsync(csvText, mode, actor.Id, cancellationToken);
            return Ok(SettingsDirectoryImportResponse<FiberEmailContactResponse>.From(
                result, FiberEmailContactResponse.From));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPut("email-contacts/onpage")]
    [RequireAdministrator]
    public async Task<IActionResult> ReplaceOnpage(
        [FromBody] OnpageEmailContactsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var contacts = await directories.ReplaceOnpageAsync(request.ToInputs(), actor.Id, cancellationToken);
            return Ok(new OnpageEmailContactsUpdateResponse(
                "ok", contacts.Select(OnpageEmailContactResponse.From).ToArray()));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("email-contacts/onpage/import")]
    [RequireAdministrator]
    public async Task<IActionResult> ImportOnpage(
        [FromBody] SettingsDirectoryCsvImportRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var (csvText, mode) = request.ToImport();
            var result = await directories.ImportOnpageAsync(csvText, mode, actor.Id, cancellationToken);
            return Ok(SettingsDirectoryImportResponse<OnpageEmailContactResponse>.From(
                result, OnpageEmailContactResponse.From));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPut("network-orders")]
    [RequireAdministrator]
    public async Task<IActionResult> ReplaceNetworkOrders(
        [FromBody] NetworkOrderCircuitsUpdateRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var records = await directories.ReplaceNetworkOrdersAsync(request.ToInputs(), actor.Id, cancellationToken);
            return Ok(new NetworkOrderCircuitsUpdateResponse(
                "ok", records.Select(NetworkOrderCircuitResponse.From).ToArray()));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("network-orders/import")]
    [RequireAdministrator]
    public async Task<IActionResult> ImportNetworkOrders(
        [FromBody] SettingsDirectoryCsvImportRequest request,
        CancellationToken cancellationToken)
    {
        var actor = AuthenticatedUserContext.GetUser(HttpContext);
        if (actor is null)
        {
            return Unauthorized(new { detail = new { code = "unauthenticated", message = "Not authenticated" } });
        }
        try
        {
            var (csvText, mode) = request.ToImport();
            var result = await directories.ImportNetworkOrdersAsync(csvText, mode, actor.Id, cancellationToken);
            return Ok(SettingsDirectoryImportResponse<NetworkOrderCircuitResponse>.From(
                result, NetworkOrderCircuitResponse.From));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
