using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class RoleQueries(IRoleDirectory roles)
{
    public async Task<IReadOnlyList<RoleDefinition>> ListAssignableRolesAsync(
        AuthenticatedUser actor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var available = await roles.GetAllAsync(cancellationToken);
        if (actor.IsAdministrator)
        {
            return available;
        }

        return available.Where(role =>
            !RoleAccessPolicy.IsAdministratorRole(role.Name)
            && !RoleAccessPolicy.IsElevatedRole(role)).ToArray();
    }

    public async Task<IReadOnlyList<RoleDefinition>> ListRoleDefinitionsAsync(
        AuthenticatedUser actor,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var available = await roles.GetAllAsync(cancellationToken);
        return actor.IsAdministrator
            ? available
            : available.Where(role => !RoleAccessPolicy.IsAdministratorRole(role.Name)).ToArray();
    }
}
