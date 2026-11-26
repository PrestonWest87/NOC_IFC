using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record LoginUserResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("role")] string? Role,
    [property: JsonPropertyName("full_name")] string? FullName,
    [property: JsonPropertyName("job_title")] string? JobTitle,
    [property: JsonPropertyName("contact_info")] string? ContactInfo,
    [property: JsonPropertyName("default_shift")] string? DefaultShift,
    [property: JsonPropertyName("theme")] string? Theme,
    [property: JsonPropertyName("account_type")] string AccountType,
    [property: JsonPropertyName("email")] string? Email,
    [property: JsonPropertyName("email_normalized")] string? EmailNormalized,
    [property: JsonPropertyName("email_verified_at")] DateTime? EmailVerifiedAt,
    [property: JsonPropertyName("is_active")] bool IsActive,
    [property: JsonPropertyName("created_at")] DateTime? CreatedAt,
    [property: JsonPropertyName("last_login_at")] DateTime? LastLoginAt,
    [property: JsonPropertyName("last_activity_at")] DateTime? LastActivityAt,
    [property: JsonPropertyName("recovery_email_status")] string RecoveryEmailStatus,
    [property: JsonPropertyName("pending_email")] string? PendingEmail,
    [property: JsonPropertyName("allowed_pages")] IReadOnlyList<string> AllowedPages,
    [property: JsonPropertyName("allowed_actions")] IReadOnlyList<string> AllowedActions,
    [property: JsonPropertyName("allowed_site_types")] IReadOnlyList<string> AllowedSiteTypes)
{
    public static LoginUserResponse From(LoginUser user) => new(
        user.Id,
        user.Username,
        user.Role,
        user.FullName,
        user.JobTitle,
        user.ContactInfo,
        user.DefaultShift,
        user.Theme,
        user.AccountType,
        user.Email,
        user.EmailNormalized,
        user.EmailVerifiedAt,
        user.IsActive,
        user.CreatedAt,
        user.LastLoginAt,
        user.LastActivityAt,
        user.RecoveryEmailStatus,
        user.PendingEmail,
        user.AllowedPages,
        user.AllowedActions,
        user.AllowedSiteTypes);
}

public sealed record LoginResponse(
    [property: JsonPropertyName("user")] LoginUserResponse User,
    [property: JsonPropertyName("token")] string Token);
