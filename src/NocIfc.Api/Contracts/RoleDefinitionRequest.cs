using System.Text.Json.Serialization;
using NocIfc.Application.Features.Identity;

namespace NocIfc.Api.Contracts;

public sealed class RoleDefinitionRequest
{
    [JsonPropertyName("name")]
    public string? Name { get; init; }

    [JsonPropertyName("allowed_pages")]
    public IReadOnlyList<string?>? AllowedPages { get; init; } = [];

    [JsonPropertyName("allowed_actions")]
    public IReadOnlyList<string?>? AllowedActions { get; init; } = [];

    [JsonPropertyName("allowed_site_types")]
    public IReadOnlyList<string?>? AllowedSiteTypes { get; init; } = [];

    public RoleDefinitionInput ToInput() =>
        new(Name, AllowedPages, AllowedActions, AllowedSiteTypes);
}
