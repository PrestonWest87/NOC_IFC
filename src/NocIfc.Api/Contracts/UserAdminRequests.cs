using System.Text.Json.Serialization;

namespace NocIfc.Api.Contracts;

public sealed class DisplayAccountRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    [JsonPropertyName("role")]
    public string? Role { get; init; }

    [JsonPropertyName("full_name")]
    public string? FullName { get; init; } = "";
}

public sealed class IndividualInviteRequest
{
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    [JsonPropertyName("email")]
    public string? Email { get; init; }

    [JsonPropertyName("role")]
    public string? Role { get; init; }

    [JsonPropertyName("full_name")]
    public string? FullName { get; init; } = "";

    [JsonPropertyName("ttl_hours")]
    public int TtlHours { get; init; } = 72;
}

public sealed class RoleChangeRequest
{
    [JsonPropertyName("role")]
    public string? Role { get; init; }
}

public sealed class UserStatusRequest
{
    [JsonPropertyName("is_active")]
    public bool? IsActive { get; init; }
}

public sealed class AdministratorResetRequest
{
    [JsonPropertyName("new_password")]
    public string? NewPassword { get; init; }
}

public sealed class UserIdentityRequest
{
    [JsonPropertyName("full_name")]
    public string? FullName { get; init; } = "";

    [JsonPropertyName("job_title")]
    public string? JobTitle { get; init; } = "";

    [JsonPropertyName("contact_info")]
    public string? ContactInfo { get; init; } = "";
}

public sealed class AccountTypeRequest
{
    [JsonPropertyName("account_type")]
    public string? AccountType { get; init; }
}

public sealed class ReviewDecisionRequest
{
    [JsonPropertyName("approve")]
    public bool? Approve { get; init; }

    [JsonPropertyName("reason")]
    public string? Reason { get; init; } = "";
}
