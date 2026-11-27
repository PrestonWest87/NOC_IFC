using System.Globalization;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.OperationalEmail;
using NocIfc.Domain.OperationalEmail;
using NocIfc.Domain.Settings;

namespace NocIfc.Api.Contracts;

public sealed record OperationalEmailTemplateResponse(
    [property: JsonPropertyName("key")] string Key,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("fields")] IReadOnlyList<OperationalEmailTemplateField> Fields,
    [property: JsonPropertyName("allows_bcc")] bool AllowsBcc,
    [property: JsonPropertyName("allows_cc")] bool AllowsCc,
    [property: JsonPropertyName("allows_attachments")] bool AllowsAttachments,
    [property: JsonPropertyName("default_subject")] string DefaultSubject,
    [property: JsonPropertyName("default_body")] string DefaultBody,
    [property: JsonPropertyName("default_to")] string DefaultTo,
    [property: JsonPropertyName("default_cc")] string DefaultCc,
    [property: JsonPropertyName("default_bcc")] string DefaultBcc,
    [property: JsonPropertyName("updated_at")] string? UpdatedAt)
{
    public static OperationalEmailTemplateResponse From(OperationalEmailTemplateView template) => new(
        template.Key,
        template.Label,
        template.Description,
        template.Fields,
        template.AllowsBcc,
        template.AllowsCc,
        template.AllowsAttachments,
        template.DefaultSubject,
        template.DefaultBody,
        template.DefaultTo,
        template.DefaultCc,
        template.DefaultBcc,
        template.UpdatedAt?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture));
}

public sealed record OperationalEmailAttachmentLimitsResponse(
    [property: JsonPropertyName("max_attachments")] int MaxAttachments,
    [property: JsonPropertyName("max_bytes_each")] int MaxBytesEach,
    [property: JsonPropertyName("max_bytes_total")] int MaxBytesTotal)
{
    public static OperationalEmailAttachmentLimitsResponse From(OperationalEmailAttachmentLimits limits) =>
        new(limits.MaxAttachments, limits.MaxBytesEach, limits.MaxBytesTotal);
}

public sealed record OperationalEmailTemplatesResponse(
    [property: JsonPropertyName("templates")] IReadOnlyList<OperationalEmailTemplateResponse> Templates,
    [property: JsonPropertyName("sender_address")] string SenderAddress,
    [property: JsonPropertyName("smtp_provider")] string SmtpProvider,
    [property: JsonPropertyName("smtp_enabled")] bool SmtpEnabled,
    [property: JsonPropertyName("timezone")] string Timezone,
    [property: JsonPropertyName("timezone_abbreviation")] string TimezoneAbbreviation,
    [property: JsonPropertyName("latest_shift_analysis")] string LatestShiftAnalysis,
    [property: JsonPropertyName("latest_shift_analysis_time")] string? LatestShiftAnalysisTime,
    [property: JsonPropertyName("attachment_limits")] OperationalEmailAttachmentLimitsResponse AttachmentLimits)
{
    public static OperationalEmailTemplatesResponse From(OperationalEmailTemplatesResult result) => new(
        result.Templates.Select(OperationalEmailTemplateResponse.From).ToArray(),
        result.SenderAddress,
        result.SmtpProvider,
        result.SmtpEnabled,
        result.Timezone,
        result.TimezoneAbbreviation,
        result.LatestShiftAnalysis,
        result.LatestShiftAnalysisTime?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture),
        OperationalEmailAttachmentLimitsResponse.From(result.AttachmentLimits));
}

public sealed record OperationalEmailReferenceDataResponse(
    [property: JsonPropertyName("fiber_contacts")] IReadOnlyList<FiberContactResponse> FiberContacts,
    [property: JsonPropertyName("onpage_contacts")] IReadOnlyList<OnpageContactResponse> OnpageContacts,
    [property: JsonPropertyName("network_orders")] IReadOnlyList<OperationalEmailNetworkOrderResponse> NetworkOrders)
{
    public static OperationalEmailReferenceDataResponse From(OperationalEmailReferenceData result) => new(
        result.FiberContacts.Select(FiberContactResponse.From).ToArray(),
        result.OnpageContacts.Select(OnpageContactResponse.From).ToArray(),
        result.NetworkOrders.Select(OperationalEmailNetworkOrderResponse.From).ToArray());
}

public sealed record FiberContactResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("company")] string Company,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("phone")] string? Phone)
{
    public static FiberContactResponse From(FiberEmailContactEntry item) =>
        new(item.Id, item.Name, item.Company, item.Email, item.Phone);
}

public sealed record OnpageContactResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("department")] string Department,
    [property: JsonPropertyName("email")] string Email)
{
    public static OnpageContactResponse From(OnpageEmailContactEntry item) =>
        new(item.Id, item.Department, item.Email);
}

public sealed record OperationalEmailNetworkOrderResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("a_location")] string ALocation,
    [property: JsonPropertyName("z_location")] string ZLocation,
    [property: JsonPropertyName("circuit_network_order_id")] string CircuitNetworkOrderId,
    [property: JsonPropertyName("company")] string Company,
    [property: JsonPropertyName("associated_circuit_network_order_ids")] IReadOnlyList<string> AssociatedCircuitNetworkOrderIds)
{
    public static OperationalEmailNetworkOrderResponse From(NetworkOrderCircuitEntry item) =>
        new(item.Id, item.ALocation, item.ZLocation, item.CircuitNetworkOrderId, item.Company,
            item.AssociatedCircuitNetworkOrderIds);
}

public sealed record OperationalEmailSignatureResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("content")] string Content,
    [property: JsonPropertyName("is_active")] bool IsActive,
    [property: JsonPropertyName("is_default")] bool IsDefault,
    [property: JsonPropertyName("created_at")] string? CreatedAt,
    [property: JsonPropertyName("updated_at")] string? UpdatedAt)
{
    public static OperationalEmailSignatureResponse From(OperationalEmailSignatureEntry signature) => new(
        signature.Id,
        signature.Name,
        signature.Content,
        signature.IsActive,
        signature.IsDefault,
        ToIsoUtc(signature.CreatedAt),
        ToIsoUtc(signature.UpdatedAt));

    private static string? ToIsoUtc(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", CultureInfo.InvariantCulture);
}
