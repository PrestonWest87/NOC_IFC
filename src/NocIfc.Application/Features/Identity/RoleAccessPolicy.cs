using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public static class RoleAccessPolicy
{
    private static readonly HashSet<string> ElevatedActions = new(StringComparer.Ordinal)
    {
        "Action: Manage Users",
        "Action: Manage Roles",
        "Action: Review Account Recovery Requests",
        "Action: Approve Recovery Email Changes",
    };

    public static bool IsAdministratorRole(string? name) =>
        string.Equals(name, "admin", StringComparison.OrdinalIgnoreCase)
        || string.Equals(name, "administrator", StringComparison.OrdinalIgnoreCase);

    public static bool IsElevatedRole(RoleDefinition? role) =>
        role is not null && role.AllowedActions.Any(ElevatedActions.Contains);
}
