using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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
    OperationalEmailSignatureCommands signatures,
    OperationalEmailSendCommands sends,
    OperationalEmailScheduleHistoryQueries schedules) : ControllerBase
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
            EnsureOnlyFields(body, "signature", "name", "content", "is_active", "is_default");
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

    [HttpPost("send")]
    public async Task<IActionResult> Send(
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            var result = await sends.SendAsync(ReadSendInput(body), user.Id, cancellationToken);
            return Ok(OperationalEmailSendResponse.From(result));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpPost("schedule")]
    public async Task<IActionResult> Schedule(
        [FromBody] JsonObject? body,
        CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            if (body is null || !body.TryGetPropertyValue("schedule", out var scheduleNode)
                || scheduleNode is not JsonObject scheduleObject)
            {
                throw new ArgumentException("Schedule configuration must be an object.");
            }
            var schedule = ReadScheduleInput(scheduleObject);
            var composeBody = body.DeepClone().AsObject();
            composeBody.Remove("schedule");
            var result = await sends.ScheduleAsync(
                ReadSendInput(composeBody), schedule, user.Id, cancellationToken);
            return Ok(OperationalEmailScheduleResponse.From(result));
        }
        catch (ArgumentException exception)
        {
            return UnprocessableEntity(new { detail = exception.Message });
        }
    }

    [HttpGet("scheduled")]
    public async Task<IActionResult> GetScheduledEmails(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 250) return UnprocessableEntity(new { detail = "limit must be between 1 and 250." });
        return Ok((await schedules.GetScheduledAsync(limit, cancellationToken))
            .Select(OperationalEmailScheduledEmailResponse.From).ToArray());
    }

    [HttpDelete("scheduled/{emailId:int}")]
    public async Task<IActionResult> CancelScheduledEmail(int emailId, CancellationToken cancellationToken)
    {
        var user = AuthenticatedUserContext.GetUser(HttpContext);
        if (user is null) return Unauthorized();
        try
        {
            return Ok(await schedules.CancelAsync(emailId, user.Id, cancellationToken));
        }
        catch (KeyNotFoundException exception)
        {
            return NotFound(new { detail = exception.Message });
        }
        catch (InvalidOperationException exception)
        {
            return Conflict(new { detail = exception.Message });
        }
    }

    [HttpGet("history")]
    public async Task<IActionResult> GetHistory(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 250) return UnprocessableEntity(new { detail = "limit must be between 1 and 250." });
        return Ok((await schedules.GetHistoryAsync(limit, cancellationToken))
            .Select(OperationalEmailDeliveryHistoryResponse.From).ToArray());
    }

    [HttpGet("history/{deliveryId:int}")]
    public async Task<IActionResult> GetDelivery(int deliveryId, CancellationToken cancellationToken)
    {
        var delivery = await schedules.GetDeliveryAsync(deliveryId, cancellationToken);
        return delivery is null
            ? NotFound(new { detail = "Email delivery was not found." })
            : Ok(OperationalEmailDeliveryDetailResponse.From(delivery));
    }

    [HttpGet("maintenance-notices")]
    public async Task<IActionResult> GetMaintenanceNotices(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 250) return UnprocessableEntity(new { detail = "limit must be between 1 and 250." });
        return Ok((await schedules.GetMaintenanceNoticesAsync(limit, cancellationToken))
            .Select(OperationalEmailSourceGroupResponse.From).ToArray());
    }

    [HttpGet("fiber-outages")]
    public async Task<IActionResult> GetFiberOutages(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default)
    {
        if (limit is < 1 or > 250) return UnprocessableEntity(new { detail = "limit must be between 1 and 250." });
        return Ok((await schedules.GetFiberOutagesAsync(limit, cancellationToken))
            .Select(OperationalEmailSourceGroupResponse.From).ToArray());
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

    private static OperationalEmailSendInput ReadSendInput(JsonObject? body)
    {
        if (body is null) throw new ArgumentException("Operational email body must be an object.");
        EnsureOnlyFields(body, "operational email",
            "template_key", "to", "cc", "bcc", "subject", "body", "fields", "attachments",
            "maintenance_notice_id", "source_email_id", "signature_id", "use_default_signature");

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        if (body.TryGetPropertyValue("fields", out var fieldsNode))
        {
            if (fieldsNode is not JsonObject fieldsObject)
            {
                throw new ArgumentException("Template fields must be an object.");
            }
            if (fieldsObject.Count > 40)
            {
                throw new ArgumentException("No more than 40 template fields may be supplied.");
            }
            foreach (var (key, value) in fieldsObject)
            {
                if (value is null) throw new ArgumentException($"{key} must be text.");
                fields[key] = ReadTextNode(value, key) ?? "";
            }
        }

        var attachments = new List<OperationalEmailAttachmentInput>();
        if (body.TryGetPropertyValue("attachments", out var attachmentsNode))
        {
            if (attachmentsNode is not JsonArray attachmentsArray)
            {
                throw new ArgumentException("Attachments must be a list.");
            }
            if (attachmentsArray.Count > 5)
            {
                throw new ArgumentException("No more than 5 attachments may be included.");
            }
            foreach (var attachmentNode in attachmentsArray)
            {
                if (attachmentNode is not JsonObject attachment)
                {
                    throw new ArgumentException("Invalid attachment payload.");
                }
                EnsureOnlyFields(attachment, "attachment", "filename", "content_type", "content_base64");
                if (!attachment.ContainsKey("filename") || !attachment.ContainsKey("content_base64"))
                {
                    throw new ArgumentException("Attachment filename and content_base64 are required.");
                }
                attachments.Add(new OperationalEmailAttachmentInput(
                    ReadSendText(attachment, "filename", allowNull: false),
                    ReadSendText(attachment, "content_type", allowNull: false),
                    ReadSendText(attachment, "content_base64", allowNull: false)));
            }
        }

        var useDefaultSignature = body.TryGetPropertyValue("use_default_signature", out var defaultNode)
            ? ReadBooleanValue(defaultNode, "use_default_signature")
            : true;
        return new OperationalEmailSendInput(
            ReadSendText(body, "template_key", allowNull: false),
            ReadSendText(body, "to", allowNull: false),
            ReadSendText(body, "cc", allowNull: false),
            ReadSendText(body, "bcc", allowNull: false),
            ReadSendText(body, "subject", allowNull: true),
            ReadSendText(body, "body", allowNull: true),
            fields,
            attachments,
            ReadInteger(body, "maintenance_notice_id"),
            ReadInteger(body, "source_email_id"),
            ReadInteger(body, "signature_id"),
            useDefaultSignature,
            body.Select(pair => pair.Key).ToHashSet(StringComparer.Ordinal));
    }

    private static string? ReadSendText(JsonObject body, string key, bool allowNull)
    {
        if (!body.TryGetPropertyValue(key, out var value)) return null;
        if (value is null)
        {
            if (allowNull) return null;
            throw new ArgumentException($"{key} must be text.");
        }
        return ReadTextNode(value, key);
    }

    private static int? ReadInteger(JsonObject body, string key)
    {
        if (!body.TryGetPropertyValue(key, out var value)) return null;
        if (value is null) return null;
        if (value is JsonValue scalar && scalar.TryGetValue<int>(out var number)) return number;
        throw new ArgumentException($"{key} must be an integer or null.");
    }

    private static bool ReadBooleanValue(JsonNode? value, string key)
    {
        if (value is JsonValue scalar && scalar.TryGetValue<bool>(out var boolean)) return boolean;
        throw new ArgumentException($"{key} must be a boolean value.");
    }

    private static OperationalEmailScheduleInput ReadScheduleInput(JsonObject body)
    {
        EnsureOnlyFields(body, "schedule", "schedule_type", "scheduled_at", "recurrence_time", "recurrence_weekday", "timezone");
        var scheduledText = ReadSendText(body, "scheduled_at", allowNull: true);
        DateTimeOffset? scheduledAt = null;
        if (scheduledText is not null)
        {
            if (!Regex.IsMatch(scheduledText, @"(?:Z|[+-]\d{2}:\d{2})$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
                || !DateTimeOffset.TryParse(scheduledText, CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var parsed))
            {
                throw new ArgumentException("One-time send must use an ISO 8601 date and time with a time zone.");
            }
            scheduledAt = parsed;
        }
        return new OperationalEmailScheduleInput(
            ReadSendText(body, "schedule_type", allowNull: false),
            scheduledAt,
            ReadSendText(body, "recurrence_time", allowNull: true),
            ReadInteger(body, "recurrence_weekday"),
            ReadSendText(body, "timezone", allowNull: false));
    }

    private static void EnsureOnlyFields(JsonObject body, string label, params string[] allowed)
    {
        var allowedSet = allowed.ToHashSet(StringComparer.Ordinal);
        var unknown = body.Select(pair => pair.Key).Where(key => !allowedSet.Contains(key))
            .OrderBy(key => key, StringComparer.Ordinal).ToArray();
        if (unknown.Length > 0)
        {
            throw new ArgumentException($"Unsupported {label} field(s): {string.Join(", ", unknown)}.");
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
