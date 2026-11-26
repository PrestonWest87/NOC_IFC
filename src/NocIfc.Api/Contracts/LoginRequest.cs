using System.Text.Json.Serialization;

namespace NocIfc.Api.Contracts;

public sealed class LoginRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }
}

public sealed class ThemeRequest
{
    [JsonPropertyName("theme")]
    public string? Theme { get; init; }
}

public sealed class ProfileUpdateRequest
{
    [JsonPropertyName("full_name")]
    public string? FullName { get; init; } = "";

    [JsonPropertyName("job_title")]
    public string? JobTitle { get; init; } = "";

    [JsonPropertyName("contact_info")]
    public string? ContactInfo { get; init; } = "";

    [JsonPropertyName("default_shift")]
    public string? DefaultShift { get; init; } = "";

    [JsonPropertyName("old_password")]
    public string? OldPassword { get; init; } = "";

    [JsonPropertyName("new_password")]
    public string? NewPassword { get; init; } = "";
}

public sealed class PasswordResetRequestBody
{
    [JsonPropertyName("identifier")]
    public string? Identifier { get; init; }
}

public sealed class PasswordResetCompletionRequest
{
    [JsonPropertyName("token")]
    public string? Token { get; init; }

    [JsonPropertyName("new_password")]
    public string? NewPassword { get; init; }
}

public sealed class RecoveryEmailRequest
{
    [JsonPropertyName("email")]
    public string? Email { get; init; }
}
