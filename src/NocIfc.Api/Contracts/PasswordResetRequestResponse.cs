using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record PasswordResetRequestResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("user_id")] int UserId,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("full_name")] string? FullName,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("email_verified")] bool EmailVerified,
    [property: JsonPropertyName("account_type")] string AccountType,
    [property: JsonPropertyName("requested_at")] DateTime? RequestedAt)
{
    public static PasswordResetRequestResponse From(PasswordResetRequestInfo request) => new(
        request.Id,
        request.UserId,
        request.Username,
        request.FullName,
        request.Email,
        request.EmailVerified,
        request.AccountType,
        request.RequestedAt);
}
