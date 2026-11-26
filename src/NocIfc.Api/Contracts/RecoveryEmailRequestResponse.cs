using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record RecoveryEmailRequestResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("user_id")] int UserId,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("full_name")] string? FullName,
    [property: JsonPropertyName("account_type")] string AccountType,
    [property: JsonPropertyName("current_email")] string? CurrentEmail,
    [property: JsonPropertyName("requested_email")] string RequestedEmail,
    [property: JsonPropertyName("requested_at")] DateTime? RequestedAt)
{
    public static RecoveryEmailRequestResponse From(RecoveryEmailRequestInfo request) => new(
        request.Id,
        request.UserId,
        request.Username,
        request.FullName,
        request.AccountType,
        request.CurrentEmail,
        request.RequestedEmail,
        request.RequestedAt);
}
