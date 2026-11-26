using System.Text.Json.Serialization;
using NocIfc.Application.Features.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed class RegistrationRequest
{
    [JsonPropertyName("token")]
    public string? Token { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    [JsonPropertyName("full_name")]
    public string? FullName { get; init; } = "";

    [JsonPropertyName("job_title")]
    public string? JobTitle { get; init; } = "";

    [JsonPropertyName("contact_info")]
    public string? ContactInfo { get; init; } = "";

    [JsonPropertyName("default_shift")]
    public string? DefaultShift { get; init; } = "No Shift";

    [JsonPropertyName("theme")]
    public string? Theme { get; init; } = "standard";

    public RegistrationInput ToInput() =>
        new(Token, Password, FullName, JobTitle, ContactInfo, DefaultShift, Theme);
}

public sealed record RegistrationInviteResponse(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("role")] string Role,
    [property: JsonPropertyName("email")] string Email,
    [property: JsonPropertyName("expires_at")] DateTime ExpiresAt)
{
    public static RegistrationInviteResponse From(RegistrationInviteInfo invite) =>
        new(invite.Username, invite.Role, invite.Email, invite.ExpiresAt);
}
