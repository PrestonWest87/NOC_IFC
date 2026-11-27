using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc;
using NocIfc.Api.Authentication;
using NocIfc.Api.Authorization;
using NocIfc.Api.Contracts;
using NocIfc.Application.Features.OperationalEmail;

namespace NocIfc.Api.Controllers;

[ApiController]
[Route("api/v1/operational-email")]
[RequirePage("Operational Email")]
public sealed class OperationalEmailController(
    OperationalEmailCatalogQueries catalog,
    OperationalEmailTemplateCommands templates,
    OperationalEmailSignatureCommands signatures) : ControllerBase
{
    [HttpGet("templates")]
    public async Task<IActionResult> GetTemplates(CancellationToken cancellationToken) =>
        Ok(OperationalEmailTemplatesResponse.From(await catalog.GetTemplatesAsync(cancellationToken)));

    [HttpGet("reference-data")]
    public async Task<IActionResult> GetReferenceData(
        [FromQuery(Name = "include_onpage")] bool includeOnpage = false,
        CancellationToken cancellationToken = default) =>
        Ok(OperationalEmailReferenceDataResponse.From(
            await catalog.GetReferenceDataAsync(includeOnpage, cancellationToken)));

    [HttpPut("templates/{templateKey}")]
    [RequireAdministrator]
    public async Task<IActionResult> UpdateTemplate(
        string templateKey,
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        try
        {
            var user = AuthenticatedUserContext.GetUser(HttpContext);
            if (user is null) return Unauthorized();
            var result = await templates.UpdateAsync(
                templateKey, ReadTemplateValues(body), user.Id, cancellationToken);
            return Ok(new { status = result.Status, template_key = result.TemplateKey });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpGet("signatures")]
    public async Task<IActionResult> GetSignatures(CancellationToken cancellationToken) =>
        Ok((await catalog.GetSignaturesAsync(false, cancellationToken))
            .Select(OperationalEmailSignatureResponse.From).ToArray());

    [HttpGet("signatures/manage")]
    [RequireAdministrator]
    public async Task<IActionResult> GetSignaturesForAdministration(CancellationToken cancellationToken) =>
        Ok((await catalog.GetSignaturesAsync(true, cancellationToken))
            .Select(OperationalEmailSignatureResponse.From).ToArray());

    [HttpPost("signatures")]
    [RequireAdministrator]
    public async Task<IActionResult> CreateSignature(
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        try
        {
            if (body is null) throw new ArgumentException("Signature body must be an object.");
            EnsureOnlyFields(body, "name", "content", "is_active", "is_default");
            var user = AuthenticatedUserContext.GetUser(HttpContext);
            if (user is null) return Unauthorized();
            var signature = await signatures.CreateAsync(
                ReadText(body, "name"),
                ReadText(body, "content"),
                ReadBoolean(body, "is_active") ?? true,
                ReadBoolean(body, "is_default") ?? false,
                user.Id,
                cancellationToken);
            return Ok(OperationalEmailSignatureResponse.From(signature));
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpPut("signatures/{signatureId:int}")]
    [RequireAdministrator]
    public async Task<IActionResult> UpdateSignature(
        int signatureId,
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        try
        {
            var user = AuthenticatedUserContext.GetUser(HttpContext);
            if (user is null) return Unauthorized();
            var updated = await signatures.UpdateAsync(signatureId, ReadSignaturePatch(body), user.Id, cancellationToken);
            return Ok(OperationalEmailSignatureResponse.From(updated));
        }
        catch (KeyNotFoundException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    [HttpDelete("signatures/{signatureId:int}")]
    [RequireAdministrator]
    public async Task<IActionResult> DeactivateSignature(int signatureId, CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            return Ok(OperationalEmailSignatureResponse.From(
                await signatures.DeactivateAsync(signatureId, user.Id, cancellationToken)));
        }
        catch (KeyNotFoundException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
        catch (ArgumentException exception)
        {
            return BadRequest(new { detail = exception.Message });
        }
    }

    private static IReadOnlyDictionary<string, string> ReadTemplateValues(JsonObject? body)
    {
        if (body is null) return new Dictionary<string, string>(StringComparer.Ordinal);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (key, node) in body)
        {
            values[key] = node is null ? "" : ReadTextNode(node, key) ?? "";
        }
        return values;
    }

    private static OperationalEmailSignaturePatch ReadSignaturePatch(JsonObject? body)
    {
        if (body is null) throw new ArgumentException("Signature update body must be an object.");
        var fields = body.Select(pair => pair.Key).ToHashSet(StringComparer.Ordinal);
        return new OperationalEmailSignaturePatch(
            ReadText(body, "name"),
            ReadText(body, "content"),
            ReadBoolean(body, "is_active"),
            ReadBoolean(body, "is_default"),
            fields);
    }

    private static void EnsureOnlyFields(JsonObject body, params string[] allowed)
    {
        var allowedSet = allowed.ToHashSet(StringComparer.Ordinal);
        var unknown = body.Select(pair => pair.Key).Where(key => !allowedSet.Contains(key))
            .OrderBy(key => key, StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported signature field(s): {string.Join(", ", unknown)}.");
        }
    }

    private static string? ReadText(JsonObject? body, string key)
    {
        if (body is null || !body.TryGetPropertyValue(key, out var value) || value is null) return null;
        return ReadTextNode(value, key);
    }

    private static string? ReadTextNode(JsonNode value, string key) =>
        value is JsonValue scalar && scalar.TryGetValue<string>(out var text)
            ? text
            : throw new ArgumentException($"{key} must be text or null.");

    private static bool? ReadBoolean(JsonObject body, string key)
    {
        if (!body.TryGetPropertyValue(key, out var value)) return null;
        if (value is JsonValue scalar && scalar.TryGetValue<bool>(out var boolean)) return boolean;
        throw new ArgumentException($"{key} must be a boolean value.");
    }
}
