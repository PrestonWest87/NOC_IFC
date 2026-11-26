using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IUserSessionResolver
{
    Task<AuthenticatedUser?> ResolveAsync(string token, CancellationToken cancellationToken);
}
