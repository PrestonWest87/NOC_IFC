using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record UserDirectoryResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("full_name")] string? FullName,
    [property: JsonPropertyName("job_title")] string? JobTitle,
    [property: JsonPropertyName("contact_info")] string? ContactInfo,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("email_verified")] bool EmailVerified,
    [property: JsonPropertyName("email_status")] string EmailStatus,
    [property: JsonPropertyName("pending_email")] string? PendingEmail,
    [property: JsonPropertyName("account_type")] string AccountType,
    [property: JsonPropertyName("role")] string? Role,
    [property: JsonPropertyName("is_active")] bool IsActive,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt,
    [property: JsonPropertyName("last_login_at")] DateTime? LastLoginAt,
    [property: JsonPropertyName("last_activity_at")] DateTime? LastActivityAt,
    [property: JsonPropertyName("invitation_pending")] bool InvitationPending)
{
    public static UserDirectoryResponse From(UserDirectoryEntry user) => new(
        user.Id,
        user.Username,
        user.FullName,
        user.JobTitle,
        user.ContactInfo,
        user.Email,
        user.EmailVerified,
        user.EmailStatus,
        user.PendingEmail,
        user.AccountType,
        user.Role,
        user.IsActive,
        user.CreatedAt,
        user.LastLoginAt,
        user.LastActivityAt,
        user.InvitationPending);
}
