using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IRoleWriter
{
    Task<bool> CreateAsync(RoleDefinition role, CancellationToken cancellationToken);
    Task<bool> UpdateAsync(RoleDefinition role, CancellationToken cancellationToken);
}
