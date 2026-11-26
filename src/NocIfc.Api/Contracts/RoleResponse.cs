using System.Text.Json.Serialization;
using NocIfc.Domain.Identity;

namespace NocIfc.Api.Contracts;

public sealed record RoleResponse(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("allowed_pages")] IReadOnlyList<string> AllowedPages,
    [property: JsonPropertyName("allowed_actions")] IReadOnlyList<string> AllowedActions,
    [property: JsonPropertyName("allowed_site_types")] IReadOnlyList<string> AllowedSiteTypes)
{
    public static RoleResponse From(RoleDefinition role) => new(
        role.Id,
        role.Name,
        role.AllowedPages,
        role.AllowedActions,
        role.AllowedSiteTypes);
}
