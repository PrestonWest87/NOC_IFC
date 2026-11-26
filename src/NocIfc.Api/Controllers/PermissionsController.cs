using Microsoft.AspNetCore.Mvc;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/permissions")]
public sealed class PermissionsController : ControllerBase
{
    [HttpGet("catalog")]
    public IActionResult GetCatalog() => Ok(PermissionCatalog.Value);
}
