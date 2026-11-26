using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IRoleDirectory
{
    Task<IReadOnlyList<RoleDefinition>> GetAllAsync(CancellationToken cancellationToken);
}
