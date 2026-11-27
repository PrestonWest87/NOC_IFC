using System.Text.Json.Serialization;

namespace NocIfc.Api.Contracts;

public sealed class EmailAttachmentRequest
{
    [JsonPropertyName("filename")]
    public string? FileName { get; init; } = "attachment";

    [JsonPropertyName("content_type")]
    public string? ContentType { get; init; } = "application/octet-stream";

    [JsonPropertyName("content_base64")]
    public string? ContentBase64 { get; init; } = "";
}

public sealed class SendEmailRequest
{
    [JsonPropertyName("to")]
    public string? To { get; init; } = "";

    [JsonPropertyName("subject")]
    public string? Subject { get; init; } = "";

    [JsonPropertyName("html_body")]
    public string? HtmlBody { get; init; } = "";

    [JsonPropertyName("attachments")]
    public IReadOnlyList<EmailAttachmentRequest?>? Attachments { get; init; } = [];
}

public sealed class BriefBroadcastRequest
{
    [JsonPropertyName("email")]
    public string? Email { get; init; } = "";
}
