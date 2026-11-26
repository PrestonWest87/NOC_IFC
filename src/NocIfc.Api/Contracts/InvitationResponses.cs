using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record PendingInvitationResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt,
    [property: JsonPropertyName("expires_at")] DateTime ExpiresAt,
    [property: JsonPropertyName("created_by")] string CreatedBy,
    [property: JsonPropertyName("revoked_at")] DateTime? RevokedAt)
{
    public static PendingInvitationResponse From(PendingRegistrationInvite invite) => new(
        invite.Id,
        invite.Username,
        invite.Email,
        invite.Role,
        invite.CreatedAt,
        invite.ExpiresAt,
        invite.CreatedBy,
        invite.RevokedAt);
}

public sealed record InvitationDeliveryResponse(
    [property: JsonPropertyName("status")] string Status,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [property: JsonPropertyName("delivery_status")] string? DeliveryStatus,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [property: JsonPropertyName("role")] string? Role,
    [property: JsonPropertyName("registration_url")] string RegistrationUrl,
    [property: JsonPropertyName("expires_at")] DateTime ExpiresAt);
