using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/settings")]
public sealed class LegacySettingsCompatibilityController(UserDirectoryQueries users) : ControllerBase
{
    [HttpGet("users")]
    [RequireAction("Tab: Settings -> Users & Roles")]
    [RequireAction("Action: Manage Users")]
    public async Task<IActionResult> GetUsers(CancellationToken cancellationToken) =>
        Ok((await users.ExecuteAsync(cancellationToken)).Select(UserDirectoryResponse.From).ToArray());
}
