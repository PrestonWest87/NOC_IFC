namespace NocIfc.Domain.Identity;

public sealed record RoleDefinition(
    int Id,
    string Name,
    IReadOnlyList<string> AllowedPages,
    IReadOnlyList<string> AllowedActions,
    IReadOnlyList<string> AllowedSiteTypes);
