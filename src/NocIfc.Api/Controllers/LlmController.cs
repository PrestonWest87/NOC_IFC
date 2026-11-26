using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Settings;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/llm")]
public sealed class LlmController(LlmConnectionTestCommands connections) : ControllerBase
{
    [HttpPost("test-connection")]
    [RequirePage("Settings & Admin")]
    [RequireAction("Tab: Settings -> AI & SMTP")]
    [RequireAdministrator]
    public async Task<IActionResult> TestConnection(
        [FromBody] LlmConnectionTestRequest request,
        CancellationToken cancellationToken) =>
        Ok(await connections.TestAsync(request.ToInput(), cancellationToken));
}
