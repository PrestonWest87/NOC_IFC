namespace NocIfc.Domain.Identity;

public sealed record AuthenticatedUser(
    int Id,
    string Username,
    string Role,
    IReadOnlyList<string> AllowedPages,
    IReadOnlyList<string> AllowedActions,
    IReadOnlyList<string> AllowedSiteTypes)
{
    public bool IsAdministrator =>
        string.Equals(Role, "admin", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Role, "administrator", StringComparison.OrdinalIgnoreCase);
}
