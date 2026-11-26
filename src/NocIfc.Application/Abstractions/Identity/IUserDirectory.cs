using NocIfc.Domain.Identity;

namespace NocIfc.Application.Abstractions.Identity;

public interface IUserDirectory
{
    Task<IReadOnlyList<UserDirectoryEntry>> GetAllAsync(CancellationToken cancellationToken);
}
