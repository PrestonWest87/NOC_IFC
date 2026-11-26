using NocIfc.Application.Abstractions.Identity;
using NocIfc.Domain.Identity;

namespace NocIfc.Application.Features.Identity;

public sealed class UserDirectoryQueries(IUserDirectory users)
{
    public Task<IReadOnlyList<UserDirectoryEntry>> ExecuteAsync(CancellationToken cancellationToken) =>
        users.GetAllAsync(cancellationToken);
}
