using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed record RoleDefinitionInput(
    string? Name,
    IReadOnlyList<string?>? AllowedPages,
    IReadOnlyList<string?>? AllowedActions,
    IReadOnlyList<string?>? AllowedSiteTypes);

public sealed class RoleCommandException(string message, int statusCode = 400, bool permissionDenied = false)
    : Exception(message)
{
    public int StatusCode { get; } = statusCode;
    public bool PermissionDenied { get; } = permissionDenied;
}

public sealed class RoleCommands(
    IRoleDirectory roles,
    IRoleWriter writer,
    SiteTypeQueries siteTypes)
{
    public async Task<bool> CreateAsync(
        AuthenticatedUser actor,
        RoleDefinitionInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var role = Prepare(input);
        EnsureDelegation(actor, role);
        ValidatePagesAndActions(role);
        var validSiteTypes = await siteTypes.ExecuteAsync(cancellationToken);
        ValidateSiteTypes(role.AllowedSiteTypes, validSiteTypes);
        return await writer.CreateAsync(role, cancellationToken);
    }

    public async Task<bool> UpdateAsync(
        AuthenticatedUser actor,
        string routeName,
        RoleDefinitionInput input,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        ValidateNameShape(input.Name);
        if (RoleAccessPolicy.IsAdministratorRole(routeName))
        {
            throw new RoleCommandException("The built-in administrator role cannot be edited.");
        }
        if (!string.Equals(routeName, input.Name, StringComparison.Ordinal))
        {
            throw new RoleCommandException("Role names cannot be changed here.");
        }

        var role = Prepare(input);
        EnsureDelegation(actor, role);
        var current = (await roles.GetAllAsync(cancellationToken))
            .FirstOrDefault(existing => string.Equals(existing.Name, routeName, StringComparison.Ordinal));
        if (current is null)
        {
            return false;
        }

        ValidatePagesAndActions(role, current);
        var validSiteTypes = await siteTypes.ExecuteAsync(cancellationToken);
        ValidateSiteTypes(role.AllowedSiteTypes, validSiteTypes, current.AllowedSiteTypes);
        return await writer.UpdateAsync(role, cancellationToken);
    }

    private static RoleDefinition Prepare(RoleDefinitionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        ValidateNameShape(input.Name);
        var name = input.Name!.Trim();
        if (name.Length == 0)
        {
            throw new RoleCommandException("Role name must contain 1-64 characters.");
        }

        return new RoleDefinition(
            0,
            name,
            Normalize(input.AllowedPages),
            Normalize(input.AllowedActions),
            Normalize(input.AllowedSiteTypes));
    }

    private static void ValidateNameShape(string? name)
    {
        if (name is null || name.Length is < 1 or > 64)
        {
            throw new RoleCommandException("Role name must contain 1-64 characters.");
        }
    }

    private static IReadOnlyList<string> Normalize(IReadOnlyList<string?>? values)
    {
        if (values is null || values.Any(value => value is null))
        {
            throw new RoleCommandException("Role grants must be arrays of strings.");
        }

        return values.Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static void EnsureDelegation(AuthenticatedUser actor, RoleDefinition role)
    {
        if (actor.IsAdministrator)
        {
            return;
        }

        if (!role.AllowedPages.All(actor.AllowedPages.Contains))
        {
            throw new RoleCommandException(
                "You cannot grant pages that your own role does not have.", 403, permissionDenied: true);
        }
        if (!role.AllowedActions.All(actor.AllowedActions.Contains))
        {
            throw new RoleCommandException(
                "You cannot grant actions or tabs that your own role does not have.", 403, permissionDenied: true);
        }
        if (!role.AllowedSiteTypes.All(actor.AllowedSiteTypes.Contains))
        {
            throw new RoleCommandException(
                "You cannot grant site types that your own role does not have.", 403, permissionDenied: true);
        }
    }

    private static void ValidatePagesAndActions(RoleDefinition role, RoleDefinition? existing = null)
    {
        var existingPages = existing?.AllowedPages.ToHashSet(StringComparer.Ordinal) ?? [];
        var existingActions = existing?.AllowedActions.ToHashSet(StringComparer.Ordinal) ?? [];
        if (role.AllowedPages.Any(value => !PermissionCatalog.ContainsPage(value) && !existingPages.Contains(value)))
        {
            throw new RoleCommandException("Role contains an unknown page permission.");
        }
        if (role.AllowedActions.Any(value => !PermissionCatalog.ContainsGrant(value) && !existingActions.Contains(value)))
        {
            throw new RoleCommandException("Role contains an unknown action or tab permission.");
        }
    }

    private static void ValidateSiteTypes(
        IReadOnlyList<string> requested,
        IReadOnlyList<string> valid,
        IReadOnlyList<string>? existing = null)
    {
        var validValues = valid.ToHashSet(StringComparer.Ordinal);
        if (existing is not null)
        {
            validValues.UnionWith(existing);
        }
        if (requested.Any(value => !validValues.Contains(value)))
        {
            throw new RoleCommandException("Role contains an unknown site type.");
        }
    }
}
