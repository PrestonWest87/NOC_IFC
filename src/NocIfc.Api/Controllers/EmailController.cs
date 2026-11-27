using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.Email;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/email")]
public sealed class EmailController(SendEmailCommands email, BriefBroadcastCommands briefs) : ControllerBase
{
    [HttpPost("broadcast-brief")]
    [RequireAnyPage("Global Dashboards", "Reporting & Briefings")]
    [RequireAction("Action: Dispatch Exec Report")]
    public async Task<IActionResult> BroadcastBrief(
        [FromBody] BriefBroadcastRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null || request.Email is null)
        {
            return UnprocessableEntity(new { detail = "A brief broadcast request is required." });
        }
        try
        {
            var result = await briefs.BroadcastUnifiedAsync(request.Email, cancellationToken);
            return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("send")]
    [RequireAction("Action: Send Email")]
    public async Task<IActionResult> Send(
        [FromBody] SendEmailRequest? request,
        CancellationToken cancellationToken)
    {
        if (request is null || request.To is null || request.Subject is null || request.HtmlBody is null
            || request.Attachments is null
            || request.Attachments.Any(attachment => attachment is null
                || attachment.FileName is null || attachment.ContentType is null || attachment.ContentBase64 is null))
        {
            return UnprocessableEntity(new { detail = "Invalid email request." });
        }

        var attachments = request.Attachments.Select(attachment => new SendEmailAttachmentInput(
            attachment!.FileName!, attachment.ContentType!, attachment.ContentBase64!)).ToArray();
        try
        {
            var result = await email.SendAsync(
                new SendEmailInput(request.To, request.Subject, request.HtmlBody, attachments), cancellationToken);
            return Ok(new { status = result.Success ? "ok" : "error", message = result.Message });
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }
}
