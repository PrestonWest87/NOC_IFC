using System.Globalization;
using System.Text.Json.Serialization;
using NocIfc.Application.Features.OperationalEmail;

namespace NocIfc.Api.Contracts;

public sealed record OperationalEmailSendDeliveryResponse(
    [property: JsonPropertyName("email_id")] int EmailId,
    [property: JsonPropertyName("delivery_id")] int DeliveryId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("sent_at")] string? SentAt,
    [property: JsonPropertyName("company"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Company)
{
    public static OperationalEmailSendDeliveryResponse From(OperationalEmailSendDelivery delivery) => new(
        delivery.EmailId,
        delivery.DeliveryId,
        delivery.Status,
        delivery.Message,
        FormatDate(delivery.SentAtUtc),
        delivery.Company);

    private static string? FormatDate(DateTime? value) =>
        value?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture);
}

public sealed record OperationalEmailSendResponse(
    [property: JsonPropertyName("email_id")] int EmailId,
    [property: JsonPropertyName("delivery_id")] int? DeliveryId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("sent_at")] string? SentAt,
    [property: JsonPropertyName("grouped"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? Grouped,
    [property: JsonPropertyName("group_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? GroupId,
    [property: JsonPropertyName("company_count"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] int? CompanyCount,
    [property: JsonPropertyName("email_ids"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<int>? EmailIds,
    [property: JsonPropertyName("delivery_ids"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<int?>? DeliveryIds,
    [property: JsonPropertyName("deliveries"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<OperationalEmailSendDeliveryResponse>? Deliveries,
    [property: JsonPropertyName("bcc_copy_deliveries"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IReadOnlyList<OperationalEmailSendDeliveryResponse>? BccCopyDeliveries)
{
    public static OperationalEmailSendResponse From(OperationalEmailSendResult result) => new(
        result.EmailId,
        result.DeliveryId,
        result.Status,
        result.Message,
        result.SentAtUtc?.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", CultureInfo.InvariantCulture),
        result.Grouped ? true : null,
        result.GroupId,
        result.CompanyCount,
        result.EmailIds,
        result.DeliveryIds,
        result.Deliveries?.Select(OperationalEmailSendDeliveryResponse.From).ToArray(),
        result.BccCopyDeliveries?.Select(OperationalEmailSendDeliveryResponse.From).ToArray());
}
