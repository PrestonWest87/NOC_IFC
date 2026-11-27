using System.Globalization;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Domain.OperationalEmail;

namespace NocIfc.Api.Contracts;

public sealed record OperationalEmailAttachmentMetadataResponse(
    [property: JsonPropertyName("filename")] string Filename,
    [property: JsonPropertyName("content_type")] string ContentType,
    [property: JsonPropertyName("size_bytes")] int SizeBytes)
{
    public static OperationalEmailAttachmentMetadataResponse From(OperationalEmailAttachmentMetadata attachment) =>
        new(attachment.FileName, attachment.ContentType, attachment.SizeBytes);
}

public sealed record OperationalEmailScheduledEmailResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("template_key")] string TemplateKey,
    [property: JsonPropertyName("created_by_user_id")] int? CreatedByUserId,
    [property: JsonPropertyName("signature_id")] int? SignatureId,
    [property: JsonPropertyName("signature_name")] string? SignatureName,
    [property: JsonPropertyName("parent_email_id")] int? ParentEmailId,
    [property: JsonPropertyName("group_id")] string? GroupId,
    [property: JsonPropertyName("group_company")] string? GroupCompany,
    [property: JsonPropertyName("bcc_copy_only")] bool BccCopyOnly,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("to")] IReadOnlyList<string> ToRecipients,
    [property: JsonPropertyName("cc")] IReadOnlyList<string> CcRecipients,
    [property: JsonPropertyName("bcc")] IReadOnlyList<string> BccRecipients,
    [property: JsonPropertyName("fields")] IReadOnlyDictionary<string, string> Fields,
    [property: JsonPropertyName("schedule_type")] string ScheduleType,
    [property: JsonPropertyName("timezone")] string Timezone,
    [property: JsonPropertyName("scheduled_at")] string? ScheduledAt,
    [property: JsonPropertyName("recurrence_time")] string? RecurrenceTime,
    [property: JsonPropertyName("recurrence_weekday")] int? RecurrenceWeekday,
    [property: JsonPropertyName("next_run_at")] string? NextRunAt,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("last_sent_at")] string? LastSentAt,
    [property: JsonPropertyName("last_error")] string? LastError,
    [property: JsonPropertyName("created_at")] string? CreatedAt,
    [property: JsonPropertyName("attachments")] IReadOnlyList<OperationalEmailAttachmentMetadataResponse> Attachments,
    [property: JsonPropertyName("message"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Message = null,
    [property: JsonPropertyName("email_ids"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<int>? EmailIds = null)
{
    public static OperationalEmailScheduledEmailResponse From(OperationalEmailScheduledEntry email) => new(
        email.Id, email.TemplateKey, email.CreatedByUserId, email.SignatureId, email.SignatureName,
        email.ParentEmailId, email.GroupId, email.GroupCompany, email.BccCopyOnly, email.Subject,
        email.ToRecipients, email.CcRecipients, email.BccRecipients, email.Fields, email.ScheduleType,
        email.Timezone, FormatUtc(email.ScheduledAt), email.RecurrenceTime, email.RecurrenceWeekday,
        FormatUtc(email.NextRunAt), email.Status, FormatUtc(email.LastSentAt), email.LastError,
        FormatUtc(email.CreatedAt), email.Attachments.Select(OperationalEmailAttachmentMetadataResponse.From).ToArray());

    private static string? FormatUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public sealed record OperationalEmailScheduleGroupResponse(
    [property: JsonPropertyName("grouped")] bool Grouped,
    [property: JsonPropertyName("group_id")] string? GroupId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("company_count")] int CompanyCount,
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("email_ids")] IReadOnlyList<int> EmailIds,
    [property: JsonPropertyName("next_run_at")] string? NextRunAt,
    [property: JsonPropertyName("emails")] IReadOnlyList<OperationalEmailScheduledEmailResponse>? Emails);

public static class OperationalEmailScheduleResponse
{
    public static object From(OperationalEmailScheduleResult result)
    {
        if (result.Grouped)
        {
            return new OperationalEmailScheduleGroupResponse(
                true,
                result.GroupId,
                result.Primary.Status,
                result.Message ?? "",
                result.CompanyCount ?? 0,
                result.Primary.Id,
                result.EmailIds ?? [],
                FormatUtc(result.NextRunAt),
                result.Emails?.Select(OperationalEmailScheduledEmailResponse.From).ToArray());
        }
        return OperationalEmailScheduledEmailResponse.From(result.Primary) with
        {
            Message = result.Message,
            EmailIds = result.EmailIds,
        };
    }

    private static string? FormatUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public sealed record OperationalEmailDeliveryHistoryResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("email_id")] int EmailId,
    [property: JsonPropertyName("template_key")] string TemplateKey,
    [property: JsonPropertyName("bcc_copy_only")] bool BccCopyOnly,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("smtp_provider")] string SmtpProvider,
    [property: JsonPropertyName("sender_address")] string? SenderAddress,
    [property: JsonPropertyName("signature_name")] string? SignatureName,
    [property: JsonPropertyName("to")] IReadOnlyList<string> ToRecipients,
    [property: JsonPropertyName("cc")] IReadOnlyList<string> CcRecipients,
    [property: JsonPropertyName("bcc")] IReadOnlyList<string> BccRecipients,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("attachment_names")] IReadOnlyList<string> AttachmentNames,
    [property: JsonPropertyName("attempted_at")] string? AttemptedAt,
    [property: JsonPropertyName("sent_at")] string? SentAt,
    [property: JsonPropertyName("error_message")] string? ErrorMessage)
{
    public static OperationalEmailDeliveryHistoryResponse From(OperationalEmailDeliveryHistoryEntry row) => new(
        row.Id, row.EmailId, row.TemplateKey, row.BccCopyOnly, row.Status, row.SmtpProvider,
        row.SenderAddress, row.SignatureName, row.ToRecipients, row.CcRecipients, row.BccRecipients,
        row.Subject, row.AttachmentNames, FormatUtc(row.AttemptedAt), FormatUtc(row.SentAt), row.ErrorMessage);

    private static string? FormatUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public sealed record OperationalEmailDeliveryDetailResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("email_id")] int EmailId,
    [property: JsonPropertyName("group_id")] string? GroupId,
    [property: JsonPropertyName("group_company")] string? GroupCompany,
    [property: JsonPropertyName("bcc_copy_only")] bool BccCopyOnly,
    [property: JsonPropertyName("template_key")] string TemplateKey,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("smtp_provider")] string SmtpProvider,
    [property: JsonPropertyName("sender_address")] string? SenderAddress,
    [property: JsonPropertyName("signature_name")] string? SignatureName,
    [property: JsonPropertyName("to")] IReadOnlyList<string> ToRecipients,
    [property: JsonPropertyName("cc")] IReadOnlyList<string> CcRecipients,
    [property: JsonPropertyName("bcc")] IReadOnlyList<string> BccRecipients,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("body")] string Body,
    [property: JsonPropertyName("fields")] IReadOnlyDictionary<string, string> Fields,
    [property: JsonPropertyName("attachment_names")] IReadOnlyList<string> AttachmentNames,
    [property: JsonPropertyName("attempted_at")] string? AttemptedAt,
    [property: JsonPropertyName("sent_at")] string? SentAt,
    [property: JsonPropertyName("error_message")] string? ErrorMessage)
{
    public static OperationalEmailDeliveryDetailResponse From(OperationalEmailDeliveryDetail row) => new(
        row.Id, row.EmailId, row.GroupId, row.GroupCompany, row.BccCopyOnly, row.TemplateKey,
        row.Status, row.SmtpProvider, row.SenderAddress, row.SignatureName, row.ToRecipients,
        row.CcRecipients, row.BccRecipients, row.Subject, row.Body, row.Fields, row.AttachmentNames,
        FormatUtc(row.AttemptedAt), FormatUtc(row.SentAt), row.ErrorMessage);

    private static string? FormatUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}

public sealed record OperationalEmailSourceGroupResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("group_id")] string? GroupId,
    [property: JsonPropertyName("grouped")] bool Grouped,
    [property: JsonPropertyName("company_count")] int CompanyCount,
    [property: JsonPropertyName("companies")] IReadOnlyList<string> Companies,
    [property: JsonPropertyName("email_ids")] IReadOnlyList<int> EmailIds,
    [property: JsonPropertyName("template_key")] string TemplateKey,
    [property: JsonPropertyName("subject")] string Subject,
    [property: JsonPropertyName("to")] IReadOnlyList<string> ToRecipients,
    [property: JsonPropertyName("cc")] IReadOnlyList<string> CcRecipients,
    [property: JsonPropertyName("bcc")] IReadOnlyList<string> BccRecipients,
    [property: JsonPropertyName("fields")] IReadOnlyDictionary<string, string> Fields,
    [property: JsonPropertyName("sent_at")] string? SentAt)
{
    public static OperationalEmailSourceGroupResponse From(OperationalEmailSourceGroup group) => new(
        group.Id, group.GroupId, group.Grouped, group.CompanyCount, group.Companies, group.EmailIds,
        group.TemplateKey, group.Subject, group.ToRecipients, group.CcRecipients, group.BccRecipients,
        group.Fields, group.SentAt?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture));
}
